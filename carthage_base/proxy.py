# Copyright (C) 2023, 2024, 2025, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

import dataclasses
import os
from pathlib import Path
import typing
from urllib.parse import urlparse
import urllib
from ipaddress import IPv4Address
import carthage.dns
import carthage.pki as pki
from carthage import *
from carthage.modeling import *
from carthage.utils import memoproperty, possibly_async
from carthage.modeling.utils import setattr_default # xxx this should move somewhere more public
from carthage.oci import *
from carthage.podman import *
from carthage.network import shared_network_links

resources_dir = Path(__file__).parent.joinpath('resources')

__all__ = []

@dataclasses.dataclass(frozen=True)
class CertInfo:

    cert_file: str
    key_file: str
    domains: tuple[str]
    
@dataclasses.dataclass()
class ProxyService:

    '''Represents a service on a :class:`ProxyServiceRole` that can beg reverse proxied.
    Typical usage::

        class service(ProxyServiceRole):
            add_provider(ProxyService(
                downstream='https://{name}/',
                service='some_service')

    That would add a service whose public facing name is the same as
    the name of the model. Carthage will attempt to determine
    plausible upstream URLs and public_names. 

    The following tokens are replaced within upstream and downstream URLS:

    ``{name}``
        The name of the model.

    ``{{upstream_ip}}``
        An ip address on which the proxy can contact the service. 
    '''
    
    upstream_url:urllib.parse.ParseResult #: URL that the proxy should contact to reach the service
    downstream_url: urllib.parse.ParseResult #: URL facing toward the public side of the proxy
    service: str #:A name to identify the service; the service and protocol need to be unique in the context of a given :class:`ProxyConfig`

    public_name: str = None #: The public name under which the service is registered in DNS; if downstream is set, must be the same as the netloc of the downstream URL.

    def __init__(
            self, *,
            downstream:str,
            upstream:str = None,
            public_name:str|bool = None,
            upstream_port:int = None,
            service=None
            ):
        if not upstream and not upstream_port:
            raise TypeError('Either upstream or upstream_port is required')
        if not upstream:
            proto = 'https' if upstream_port in {443, 8443} else 'http'
            if upstream_port in (443, 80):
                portstr = ''
            else:
                portstr = f':{upstream_port}'
            upstream = f'{proto}://{{upstream_ip}}{portstr}/'
        self.upstream = upstream
        self.downstream = downstream
        if not service:
            service = self.downstream_url.netloc+'-'+self.downstream_url.scheme
        self.service = service
        if public_name:
            self.public_name = public_name
        elif public_name is False:
            self.public_name = None

    @property
    def downstream(self):
        return self.downstream_url.geturl()

    @downstream.setter
    def downstream(self, url):
        self.downstream_url = urlparse(url)
        return url

    @property
    def upstream(self):
        return self.upstream_url.geturl()

    @upstream.setter
    def upstream(self, url):
        self.upstream_url = urlparse(url)
        return url

    async def resolve_for_model(self, model, config:'proxyConfig'):
        def sub(s:str):
            s = s.replace('{name}', model.name)
            s = s.replace('{upstream_ip}', upstream_ip)
            return s
        if hasattr(model, 'proxy_address'):
            upstream_ip = str(await resolve_deferred(
                model.ainjector,
                item=model.proxy_address,
                args={'server':config.server,
                      'config':config,
                      }))
        else:
            upstream_ip = ''
        self.upstream = sub(self.upstream)
        self.downstream = sub(self.downstream)

    def default_instance_injection_key(self):
        return InjectionKey(ProxyService, service=self.service)
    

    @memoproperty
    def public_name(self):
        return self.downstream_url.netloc
    
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

    #: TTL for dns records
    dns_ttl = 30
    server: MachineModel
    services: list[ProxyService]
    proxied_models: list[MachineModel]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.services = {}
        self.proxied_models = []
        self.certificates = []
        self.server = None

    def add_proxied_model(self, model):
        '''
        Record a MachineModel that should be called to register proxy services.
        '''
        if model not in self.proxied_models:
            self.proxied_models.append(model)
            
    def add_proxy_service(self, service:ProxyService):
        self.services[service.upstream] = service

    def add_certificate(self, cert:CertInfo):
        self.certificates = list(filter( lambda c: c.cert_file != cert.cert_file, self.certificates))
        self.certificates.append(cert)

    def set_server(self, server:MachineModel):
        if self.server and (server is not self.server):
            raise RuntimeError(f'server already set; refusing to modify from {self.server} to {server}')
        self.server = server

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

        runas_user = 'root'
        
        @setup_task("Install Software")
        async def install_software(self):
            await self.run_command(
                'apt', 'update')
            await self.run_command(
                'apt', '-y', 'install', 'apache2')
            await self.run_command('a2enmod', 'proxy', 'headers', 'ssl', 'proxy_http')

__all__ += ['ProxyImageRole']

class CertbotCertRole(ImageRole, SetupTaskMixin, AsyncInjectable):

    '''
    Sets up a proxy server to use a single letsencrypt certificate.
    Does not actually  call certbot yet.

    configuration:

    certbot_email
        Email for important account updates

    certbot_production_certificates
        If true, get production certificates
    
    '''

    add_provider(pki.contact_trust_store_key, pki.LetsencryptTrustStore)

    certbot_email = None
    certbot_production_certificates = True

    async def setup_certificate_info(self):
        self.cert_info = None
        if isinstance(self, MachineModel):
            config = await self.ainjector.get_instance_async(ProxyConfig)
            domains = list(config.ssl_certificates_needed())
            domains.sort()
            if domains:
                self.cert_info = CertInfo(
                    cert_file=f'/etc/letsencrypt/live/{domains[0]}/fullchain.pem',
                    key_file=f'/etc/letsencrypt/live/{domains[0]}/privkey.pem',
                domains=tuple(domains)
                                  )
                config.add_certificate(self.cert_info)
        return await super().setup_certificate_info()

    class install_certbot(FilesystemCustomization):

        runas_user = 'root'
        
        @setup_task("Install Certbot")
        async def install_certbot_task(self):
            await self.run_command('apt', 'update')
            await self.run_command(
                'apt', '-y', 'install',
                'certbot', 'python3-certbot-apache'
                )
            fn = self.path/'etc/letsencrypt/renewal-hooks/deploy/10-apache'
            fn.parent.mkdir(parents=True, exist_ok=True)
            with fn.open('w') as f:
                f.write('#!/bin/bash\n\nservice apache2 reload\n')
            await self.run_command('chmod', 'a+x', '/etc/letsencrypt/renewal-hooks/deploy/10-apache')

        @setup_task("get certificates")
        async def get_certificates(self):
            if getattr(self.model, 'cert_info', None):
                domains = self.model.cert_info.domains
                if not domains: raise SkipSetupTask
                if not self.model.certbot_email:
                    logger.warning('Certbot disabled because email not set')
                    raise SkipSetupTask
                test_argument = tuple() if self.model.certbot_production_certificates else ('--test-cert',)
                await self.run_command(
                    'certbot',
                    '-n',
                    '--apache',
                    '-d', ','.join(domains),
                    '-n',
                    '--agree-tos',
                    '-m', self.model.certbot_email,
                    *test_argument)
            else: raise SkipSetupTask

        @get_certificates.hash()
        def get_certificates(self):
            try:
                domains = list(self.model.cert_info.domains)
            except (AttributeError,KeyError): return ""
            domains.sort()
            return ",".join(domains)
            
            
            

__all__ += ['CertbotCertRole']

@inject(manager=InjectionKey(pki.PkiManager, _ready=True))
async def  pki_manager_contact_trust_store(manager):
    return await manager.trust_store()

    
        
class PkiCertRole(ImageRole, SetupTaskMixin, AsyncInjectable):

    '''Populate certs with :class:`carthage.pki.PkiManager`, a very simple CA that stores state in *state_dir*.
    '''

    add_provider(pki.contact_trust_store_key, pki_manager_contact_trust_store)

    async def setup_certificate_info(self):
        if isinstance(self, MachineModel):
            config = await self.ainjector.get_instance_async(ProxyConfig)
            setattr_default(self, 'pki_manager_domains', [])
            for domain in config.ssl_certificates_needed():
                self.pki_manager_domains.append(domain)
                config.add_certificate(CertInfo(
                    cert_file=f'/etc/pki/{domain}',
                    key_file=f'/etc/pki/{domain}',
                    domains=(domain,),
                ))
        return await super().setup_certificate_info()

    @inject_autokwargs(
        pki=InjectionKey(pki.PkiManager,_ready=True),
        )
    class install_certs_cust(FilesystemCustomization):

        runas_user = 'root'
        
        @setup_task("Install and Generate Certificates")
        async def install_certs(self):
            if not isinstance(self.model, MachineModel): raise SkipSetupTask
            await self.model.async_become_ready()
            pki_path = self.path/"etc/pki"
            pki_path.mkdir(mode=0o700, exist_ok=True)
            for d in self.model.pki_manager_domains:
                domain_path = pki_path/d
                if domain_path.exists(): continue
                c = await self.pki.issue_credentials_onefile(d, f'PkiCertsRole {self.model.name}')
                domain_path.write_text(c)
                
__all__ += ['PkiCertRole']


class ProxyProtocol(MachineModel, template=True):

    '''
    Responsible for implementing the proxy side of :class:`ProxyServiceRole`. This protocol includes:

    * Register the proxy as the server in the :class:`ProxyConfig` at model resolution time

    * At :meth:`async_ready` time, ask each*ProxyServiceRole* to register its proxy map.

    * Providing code to update proxy DNS. Note this code is not hooked into a setup_task by this protocol class; that is the job of the actual proxy implementation.

    '''

    #: If True, updateproxy dns whenever the machine starts
    update_dns_on_start:bool = True
    
    #: A list of public IPs or a function returning public_ips
    proxy_public_ips: typing.Union[typing.Callable, list]
    @inject(host_model=InjectionKey(container_host_model_key, _optional=True))
    async def proxy_public_ips(self, host_model):
        if not issubclass(self.machine_type, OciContainer):
            raise NotImplementedError('It is not yet implemented how to deal with non-containerized ProxyServiceRole')
        
        if host_model:
            machine = await host_model.ainjector.get_instance_async(InjectionKey(Machine, _ready=False))
            await machine.is_machine_running()
            if not machine.running: await machine.start_machine()
            public_ips = set(
                    l.merged_v4_config.public_address for l in host_model.network_links.values())
            public_ips -= {None}
            return list(map(lambda a: str(a), public_ips))
        else:
            logger.warn(f'{self.name} could not find container_host_model; no public addresses.  Set container_host_model_key appropriately.')
            return []

    #: A list of private IPs to use for proxy dns, or a function returning the same
    proxy_private_ips: typing.Union[typing.Callable, list]
    @inject(host_model=InjectionKey(container_host_model_key, _optional=True))
    async def proxy_private_ips(self, host_model):
        if not issubclass(self.machine_type, OciContainer):
            raise NotImplementedError('It is not yet implemented how to deal with non-containerized ProxyServiceRole')
        
        if host_model:
            machine = await host_model.ainjector.get_instance_async(InjectionKey(Machine, _ready=False))
            await machine.is_machine_running()
            if not machine.running: await machine.start_machine()
            private_ips = set(
                l.merged_v4_config.address for l in host_model.network_links.values())
            try:
                private_ips.add(IPv4Address(machine.ip_address))
            except Exception: pass
            private_ips -= {None, IPv4Address('127.0.0.1')}

            return list(map(lambda a: str(a), private_ips))
        else:
            logger.warn(f'{self.name} could not find container_host_model; no addresses.  Set container_host_model_key appropriately.')
            return []

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.injector.add_event_listener(InjectionKey(Machine), ['start_machine'], self.update_proxy_dns_event)
        
    async def resolve_model(self, force=False):
        await super().resolve_model(force=force)
        self.proxy_config = await self.ainjector.get_instance_async(ProxyConfig)
        self.proxy_config.set_server(self)

    async def async_ready(self):
        await self.resolve_model(False)
        for model in self.proxy_config.proxied_models:
            await model.register_proxy_map(self.proxy_config)
        await self.setup_certificate_info()
        await super().async_ready()

    async def update_proxy_dns_event(self, **kwargs):
        '''
        An event handler.  If this model is configured to update DNS on machine start, then update DNS by calling update_prxy_dns.
        '''
        if self.update_dns_on_start:
            await self.update_proxy_dns()
            
    async def update_proxy_dns(self):
        '''
        Should be called from a context where the IP addresses are available; for cloud instances this probably means that the implementation of this model is running.
        Updates DNS records for all proxy services registered with this model.
        '''
        
        config = self.proxy_config
        logger.debug('Updating Proxy DNS for %s', self.name)
        found_addresses = False
        for s in config.services.values():
            if not s.public_name : continue
            public_ips = self.proxy_public_ips
            private_ips = self.proxy_private_ips
            if callable(public_ips):
                public_ips = await self.ainjector(public_ips)
            public_records = None
            private_records = None
            logger.info('Update DNS for proxied service %s', s.public_name)
            if  public_ips:
                public_records=[('A', public_ips)]
            if callable(private_ips):
                private_ips = await self.ainjector(private_ips)
            if private_ips:
                private_records = [('A', private_ips)]
            if public_ips or private_ips:
                found_addresses = True
                await self.ainjector(
                    carthage.dns.update_dns_for,
                        public_name=s.public_name if public_records else None,
                    private_name=s.public_name if private_records else None,
                        public_records=public_records,
                        private_records=private_records,
                ttl=config.dns_ttl)
        return found_addresses

class ProxyServerRole(ProxyProtocol, ProxyImageRole, template=True):

    self_provider(InjectionKey(ProxyProtocol))
    add_provider(ProxyConfig)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.injector.replace_provider(InjectionKey('by_server_path'), self.by_server_path)
                                       
    
    proxy_conf_task = mako_task('proxy.conf', by_server_path=InjectionKey('by_server_path'),
                                certs_by_domain=InjectionKey('certs_by_domain'),
                                output='etc/apache2/conf-enabled/proxy.conf')

    @inject(config=ProxyConfig)
    async def by_server_path(self, config):
        return config.by_downstream_server_path()

    @inject(config=ProxyConfig)
    async def certs_by_domain(config):
        return config.certs_by_server()


    async def setup_certificate_info(self):
        '''
        Called after all proxy services have been registered to actually populate ProxyConfig.certificates.
        A stub; implemented in certificate roles.
        '''
        if hasattr(super(), 'setup_certificate_info'):
            raise TypeError('ProxyServerRole needs to come to the right of any certificate provider.')
        
    class proxy_server_cust(FilesystemCustomization):
        runas_user = 'root'
        install_mako = install_mako_task('model')

            
__all__ += ['ProxyServerRole']

@inject(base_image=None)
class ProxyContainerImage(ProxyImageRole, PodmanImageModel):
    oci_image_tag = 'localhost/proxy:latest'
    base_image = 'debian:latest'
    oci_image_command = ['apache2ctl', '-D', 'FOREGROUND']

__all__ += ['ProxyContainerImage']

public_name_key = InjectionKey('carthage_base.public_name')

__all__ += ['public_name_key']

class ProxySystemDependency(SystemDependency):

    name = 'proxy_dependency'

    async def __call__(self, ainjector):
        server = await ainjector.get_instance_async(InjectionKey(ProxyProtocol, _ready=True))
        await server.machine.async_become_ready()
        if not await server.machine.is_machine_running():
            await server.machine.start_machine()

@inject(config=ProxyConfig)
def find_proxy_server(config):
    '''
    Added to the ProxyServiceInjector so that asking for ProxyProtocol from any proxy service will yield the proxy it is using. This function (and thus that provider) will fail if called before the proxy model is resolved.
    '''
    return config.server

@inject(model=AbstractMachineModel)
def default_public_name(model):
    return model.name

class ProxyServiceRole(MachineModel, AsyncInjectable, template=True):

    add_provider(ProxySystemDependency())
    add_provider(pki.contact_trust_store_key, injector_xref(
        InjectionKey(ProxyProtocol),
        pki.contact_trust_store_key))
    add_provider(public_name_key, default_public_name, overridable_default=True)
    async def proxy_address(self, server:ProxyProtocol):
        '''
        Returns the address at which the proxy should contact this proxy service.
        '''
        for links in shared_network_links(self.network_links, server.network_links):
            if address := links[0].merged_v4_config.address:
                return address
        try:
            return self.ip_address
        except NotImplementedError:
            raise RuntimeError('Could not find address for proxy to contact on') from None
        
    async def register_proxy_map(self, config:ProxyConfig):
        filter_result = await self.ainjector.filter_instantiate_async(
            ProxyService, ['service'],
            stop_at = self.ainjector)
        services =[x[1] for x in filter_result]
        for s in services:
            await s.resolve_for_model(self, config)
            config.add_proxy_service(s)
        
    async def resolve_model(self, force=False):
        await super().resolve_model(force=force)
        proxy_server = await self.ainjector.get_instance_async(InjectionKey(ProxyProtocol, _ready=False))
        self.proxy_config = await proxy_server.ainjector.get_instance_async(ProxyConfig)
        self.proxy_config.add_proxied_model(self)
    
            
__all__ += ['ProxyServiceRole']

def le_staging_cert_info():
    for tag in 'letsencrypt-stg-root-x1', 'letsencrypt-stg-root-x2':
        yield tag, resources_dir.joinpath(tag+'.pem').read_text()

LetsEncryptStagingCustomization = carthage.pki.install_root_cert_customization(le_staging_cert_info)

__all__ += ['LetsEncryptStagingCustomization']

def build_proxy_service(service, ssl:bool=True, force_ip:bool=False):
    '''
    Usage::

        add-provider(build_proxy_service('keycloak', ssl=False))

    Will generate the service based on public_name_key.  Will use *upstream_ip* if *force_ip* or if the model's name is the same as the public_name.

    '''
    @inject(public_name=public_name_key,
            model=AbstractMachineModel)
    class ThisService(ProxyService, Injectable):
        @classmethod
        def default_class_injection_key(cls):
            return InjectionKey(ProxyService, service=service)
        def __init__(self, model, public_name, **kwargs):
            nonlocal force_ip
            if model.name == public_name:
                force_ip = True
            upstream_name = model.name if not force_ip else '{upstream_ip}'
            upstream_proto = 'https' if ssl else 'http'
            upstream = f'{upstream_proto}://{upstream_name}/'
            super().__init__(
            service=service,
            downstream=f'https://{public_name}/',
            upstream=upstream, **kwargs)
    return ThisService

__all__ += ['build_proxy_service']

async def public_names_for(model):
    '''
    Return all the public names for a model based on ProxyServices it provides and on its public_name_key.
    '''
    try:
        public_name = await model.ainjector.get_instance_async(public_name_key)
    except KeyError:
        public_name = None
    config = model.injector(ProxyConfig)
    filter_result = await model.ainjector.filter_instantiate_async(
        ProxyService, ['service'],
        stop_at = model.ainjector)
    services =[x[1] for x in filter_result]
    for s in services:
            await s.resolve_for_model(model, config)
    public_names = set(s.public_name for s in services if s.public_name)
    if public_name:
        public_names |= {public_name}
    return list(public_names)

__all__ += ['public_names_for']
