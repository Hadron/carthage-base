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
from carthage import *
from carthage.modeling import *
from carthage.utils import memoproperty
from carthage.oci import *
from carthage.podman import *

__all__ = []

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
    
__all__ += ['ProxyService']

class ProxyConfig(InjectableModel):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.services = {}

    def add_proxy_service(self, service:ProxyService):
        self.services[service.upstream] = service

    def by_downstream_server_path(self):
        result = {}
        for s in self.services.values():
            result.setdefault(s.downstream_server, {})
            result[s.downstream_server][s.downstream_url.path] = s
        return result
    
        
__all__ += ['ProxyConfig']

class ProxyImage(ImageRole):

    class proxy_customizations(FilesystemCustomization):

        @setup_task("Install Software")
        async def install_software(self):
            await self.run_command(
                'apt', 'update')
            await self.run_command(
                'apt', '-y', 'install', 'apache2')
            await self.run_command('a2enmod', 'proxy')

class ProxyServerRole(MachineModel, ProxyImage, template=True):

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
            
            
__all__ += ['ProxyServiceRole']
