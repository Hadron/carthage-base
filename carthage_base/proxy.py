# Copyright (C) 2023, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

import dataclasses
import os
from pathlib import Path
from urllib.parse import urlparse
import carthage.pki
from carthage import *
from carthage.modeling import *
from carthage.utils import memoproperty
from carthage.modeling.utils import setattr_default # xxx this should move somewhere more public
from carthage.oci import *
from carthage.podman import *

__all__ = []

@dataclasses.dataclass(frozen=True)
class CertInfo:

    cert_file: str
    key_file: str
    domains: tuple[str]
    
@dataclasses.dataclass(frozen=True)
class ProxyService(InjectableModel):

    '''
    Represents a request from a :class:`MachineModel` for some service to be reverse proxied into the machine.

    Typical usage is that there is a proxy micro service on a container host that claims port 443 (and possibly 80).  It collects :class:`ProxyService` from its injector up to the point where :class:`ProxyConfig` is defined and reverse proxies for each service.

    This class is indexed by an ``InjectionKey(ProxyService, service=service_name, proto=http|https)``.  It might appear convenient if the class were indexed by an *InjectionKey* containing *upstream_url* as a constraint.  That would require the URL be computable in all cases at compilation time for it to properlyp propagate up.  Depending on how networking is configured, that may not be possible.


    Typical usage: this class is not typically directly instantiated. But in cases where the configuration is known it could be instantiated like::

        add_provider(InjectionKey(ProxyService, service=service_name, proto=proto),
            when_needed(ProxyService, upstream_url=url1, downstream_url=url2, service=service_name), propagate=True)

    '''
    
    upstream:str #: URL that the proxy should contact to reach the service
    downstream: str #: URL facing toward the public side of the proxy
    service: str #:A name to identify the service; the service and protocol need to be unique in the context of a given :class:`ProxyConfig`

    def __post_init__(self):
        object.__setattr__(self, 'upstream_url', urlparse(self.upstream))
        object.__setattr__(self, 'downstream_url', urlparse(self.downstream))

    @property
    def upstream_server(self):
        '''The host associated with the upstream URL'''
        return self.upstream_url.netloc

    @property
    def downstream_server(self):
        '''The server component of the downstream URL'''
        return self.downstream_url.netloc

    @property
    def downstream_proto(self):
        return self.downstream_url.scheme
    
__all__ += ['ProxyService']

class ProxyConfig(InjectableModel):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.services = {}
        self.certificates = []

    def add_proxy_service(self, service:ProxyService):
        self.services[service.upstream] = service

    def add_certificate(self, cert:CertInfo):
        self.certificates = list(filter( lambda c: c.cert_file != cert.cert_file, self.certificates))
        self.certificates.append(cert)
        
    def by_downstream_server_path(self):
        result = {}
        for s in self.services.values():
            result.setdefault((s.downstream_proto,s.downstream_server), {})
            result[(s.downstream_proto, s.downstream_server)][s.downstream_url.path] = s
        return result

    def certs_by_server(self):
        result = {}
        for c in self.certificates:
            for d in c.domains:
                assert d not in result or result[d] is c, \
                    f'Two different certificates cover {d}'
                result[d] = c
        return result

    def ssl_servers(self):
        return tuple(s for p, s in self.by_downstream_server_path() if p == 'https')

    def ssl_certificates_needed(self):
        return set(self.ssl_servers()) - set(self.certs_by_server())
    
                    
        
__all__ += ['ProxyConfig']

class ProxyImageRole(ImageRole):

    class proxy_customizations(FilesystemCustomization):

        @setup_task("Install Software")
        async def install_software(self):
            await self.run_command(
                'apt', 'update')
            await self.run_command(
                'apt', '-y', 'install', 'apache2')
            await self.run_command('a2enmod', 'proxy', 'headers')

__all__ += ['ProxyImageRole']

class PkiCertRole(MachineModel, AsyncInjectable, template=True):

    '''Populate certs with :class:`carthage.pki.PkiManager`, a very simple CA that stores state in *state_dir*.
    '''
    
    async def async_ready(self):
        config = await self.ainjector.get_instance_async(ProxyConfig)
        setattr_default(self, 'pki_manager_domains', [])
        for domain in config.ssl_certificates_needed():
            self.pki_manager_domains.append(domain)
            config.add_certificate(CertInfo(
                cert_file=f'/etc/pki/{domain}',
                key_file=f'/etc/pki/{domain}',
                domains=(domain,),
                ))
        return await super().async_ready()

    @inject_autokwargs(
        pki=InjectionKey(carthage.pki.PkiManager,_ready=True),
        )
    class install_certs_cust(FilesystemCustomization):

        @setup_task("Install and Generate Certificates")
        async def install_certs(self):
            await self.model.async_become_ready()
            pki_path = self.path/"etc/pki"
            pki_path.mkdir(mode=0o700, exist_ok=True)
            for d in self.model.pki_manager_domains:
                domain_path = pki_path/d
                if domain_path.exists(): continue
                domain_path.write_text(self.pki.credentials(d))
                
__all__ += ['PkiCertRole']


class ProxyServerRole(MachineModel, ProxyImageRole, template=True):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.injector.replace_provider(InjectionKey('by_server_path'), self.by_server_path)
                                       
    
    proxy_conf_task = mako_task('proxy.conf', by_server_path=InjectionKey('by_server_path'),
                                output='etc/apache2/conf-enabled/proxy.conf')

    @inject(config=ProxyConfig)
    async def by_server_path(self, config):
        return config.by_downstream_server_path()

    class proxy_server_cust(FilesystemCustomization):
        install_mako = install_mako_task('model')
        
__all__ += ['ProxyServerRole']

class ProxyServiceRole(MachineModel, AsyncInjectable, template=True):

    async def register_container_proxy_services(self):
        '''

        Based on :class:`ports a container exposes <OciExposedPort>`, infer :class:`ProxyServices` to configure for a container providing a service.

        If port 80 or 443 is exposed, then register a service.  The following options will be used for the upstream proxy address in decreasing priority order:

        * if a *host_ip* is specified in the :class:`OciExposedPort`, then that IP and the *host_port* will be used.

        * If *proxy_address* is set on the model and *proxy_address_use_host_port*  is not falsy, then *proxy_address* will be used with  the *host_port*.  This describes the situation where *proxy_address* corresponds to an interface on the container host.

        * If *proxy_address* is set on the model and *proxy_address_use_host_port* is not set or is falsy, then *proxy_address* will be used with the *container_port*.  This describes the situation where *proxy_address* is an IP address on the container.

        * if *ip_address* is set on the model, it will be used with the *container_port*.

        * If the container is a :class:`carthage.podman.PodmanContainer`, then ``host.containers.internal`` will be used with the *host_port*.

        '''
        config = await self.ainjector.get_instance_async(ProxyConfig)
        ports = self.injector.filter_instantiate(OciExposedPort, ['container_port'])
        fallback_addr_uses_host_port = False
        fallback_addr = getattr(self, 'proxy_address', None)
        if fallback_addr:
            fallback_addr_uses_host_port = getattr(self, 'proxy_address_uses_host_port', False)
        else:
            fallback_addr = getattr(self, 'ip_address', None)
            if fallback_addr is None \
               and issubclass(self.machine_type, PodmanContainer):
                fallback_addr = 'containers.host.internal'
                fallback_addr_uses_host_port = True
                
        for key, exposed_port in ports:
            if exposed_port.container_port not in (80, 443): continue
            port = exposed_port.container_port
            host_port = exposed_port.host_port
            if port == 80: proto ='http'
            elif port == 443: proto = 'https'
            else: raise ValueError('Unable to figure out protocol')
            upstream_addr = exposed_port.host_ip
            if upstream_addr == '0.0.0.0' or upstream_addr == '127.0.0.1':
                upstream_addr = fallback_addr
                if fallback_addr_uses_host_port: port = host_port
            else:
                # We are using the host_ip from the OciExposedPort
                port = host_port
            if upstream_addr is None:
                raise ValueError('Cannot figure out upstream address')
            config.add_proxy_service(ProxyService(
                service=(self.name if proto == 'http' else self.name+'-'+proto),
                upstream=f'{proto}://{upstream_addr}:{port}/',
                downstream=f'https://{self.name}/',
                ))

    async def register_proxy_map(self):
        # Long term this should be expanded to allow the model to override proxy services, or specify them if the model will not be implemented by a container.
        # For now all we support is the container logic
        await self.register_container_proxy_services()

    async def resolve_networking(self, force=False):
        # register the proxy services at this phase, because it is guaranteed to always happen on layout initialization
        # Resolve networking might better be thought of as a phase where models announce properties that influence other models, but we have not actually caught up with that concept
        await self.register_proxy_map()
        return await super().resolve_networking(force=force)
    
            
__all__ += ['ProxyServiceRole']
