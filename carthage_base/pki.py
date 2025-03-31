# Copyright (C) 2018, 2019, 2020, 2021, 2022, 2025, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
import asyncio
import contextlib
from pathlib import Path
import re

from carthage import *
from carthage.pki import PkiManager
from carthage.pki_utils import *
from carthage.modeling import *
from carthage.ansible import ansible_role_task
import carthage.setup_tasks
from carthage.pki import *


__all__ = []

@inject(pki=InjectionKey(PkiManager, _ready=True))
class CertificateInstallationTask(carthage.setup_tasks.TaskWrapperBase):

    '''
    Usage::

        class customize(FilesystemCustomization):
            install_certificates = CertificateInstallationTask(cert=filename, key=filename, ca=filename)

    :param cert: The path relative to the host where the certificate should be installed.

    :param key: The path relative to the host where the key should be installed. If not specified, the key is prepended to the certificate.

    :param ca: The path relative to the host where the CA bundle for the :class:`~carthage.pki.PkiManager` should be installed.

    All arguments are run through :func:`~carthage.dependency_injection.resolve_deferred`.  Strings, InjectionKeys, and functions are accepted.

    '''

    cert:str
    key: str|None
    ca: str|None


    def __init__(self, *,
                 cert, key=None, ca=None,
                 dns_name=None,
                 **kwargs):
        if isinstance(cert, str):
            description = f'Install certificate to {cert}'
        else:
            description = 'Install certificate'
        super().__init__(
            description=description,
        **kwargs)
        self.dependencies_always = True #In volumes, mount even for check_completed
        self.dns_name = dns_name
        self.cert = cert
        self.key = key
        self.ca = ca
        
    @staticmethod
    def _path(instance):
        '''
        Returns either path or state_path depending on which is set.
        '''
        res = getattr(instance, 'path', None) or instance.state_path
        return Path(res)

    async def _resolve_args(self, instance):
        '''
        dns_name, cert, key, ca = await self._resolve_args(instance)
        '''
        ainjector = instance.ainjector
        results = await resolve_deferred(
            ainjector,
    item=[self.dns_name, self.cert, self.key, self.ca],
    args={})
        results = (results[0],)+tuple((relative_path(x) if x is not None else None) for x in results[1:])
        return results
        
    async def func(self, instance, pki):
        path = self._path(instance)
        dns_name, cert, key, ca = await self._resolve_args(instance)
        dns_name = dns_name or instance.name
        carthage.utils.validate_shell_safe(dns_name)
        key_pem, cert_pem = await pki.issue_credentials(dns_name, f'Credentials for {cert}')
        trust_store = await  pki.trust_store()
        ca_file = await trust_store.ca_file()
        ca_pem = ca_file.read_text()
        if key:
            key_dir = (path/key).parent
            key_dir.mkdir(mode=0o700, exist_ok=True, parents=True)
        cert_dir = (path/cert).parent
        cert_dir.mkdir(mode=0o755, exist_ok=True, parents=True)
        if ca:
            ca_dir = (path/ca).parent
            ca_dir.mkdir(exist_ok=True, parents=True)
            (path/ca).write_text(ca_pem)
        if not key:
            (path/cert).write_text(key_pem+cert_pem)
        else:
            (path/key).write_text(key_pem)
            (path/cert).write_text(cert_pem)
            
    async def check_completed_func(self, instance):
        try:
            path = self._path(instance)
            dns_name, cert, *rest = await self._resolve_args(instance)
            cert_path = (path/cert)
            stat = cert_path.stat()
            if certificate_is_expired(cert_path.read_text(), days_left=14, fraction_left=0.33):
                return False
            return stat.st_mtime
        except FileNotFoundError: return False
        except Exception:
            logger.exception('determining certificate installation')
            return False

    @memoproperty
    def stamp(self):
        if isinstance(self.cert, str):
            return f'cert_{self.cert.replace("/", "-")}'
        raise NotImplementedError
    
__all__ += ['CertificateInstallationTask']


class ContainedEntanglementPkiManager(PkiManager):
    '''
    Similar to :class:`carthage.pki.EntanglementPkimanager` except runs in a Machine such as a container rather than locally out of the Carthage state directory.
    '''

    machine: carthage.machine.Machine



    #: Where in the machine filesystem are certs and keys stored?
    pki_dir = '/etc/pki'
    #: If non-none, access pki_dir via this (potentially absolute) path.  If ca is a container, and pki_dir is mounted from the host, pki_access_dir may need to be set.
    pki_access_dir = None
    ca_name = 'Root CA'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pki_dir = relative_path(self.__class__.pki_dir)
        # It's important that self.pki_access_dir not be relative pathed.
    async def ca_cert_pem(self):
        machine = self.machine
        if isinstance(self, MachineModel):
            await machine.async_become_ready()
        cust = await machine.ainjector(FilesystemCustomization, machine)
        async with cust.customization_context:
            pki_dir = cust.path.joinpath(self.pki_access_dir or self.pki_dir)
            ca_path = pki_dir.joinpath('ca.pem')
            try:
                ca = ca_path.read_text()
                if certificate_is_expired(ca, days_left=14, fraction_left=0.33):
                    ca_path.unlink()
                    raise FileNotFoundError
                return ca
            except FileNotFoundError:
                await cust.run_command(
                    'entanglement-pki',
                    '--pki-dir='+str(self.pki_dir),
                    '--ca-name='+self.ca_name)
                return ca_path.read_text()

    async def issue_credentials(self, dns_name, tag):
        machine = self.machine
        if isinstance(self, MachineModel):
            await machine.async_become_ready()
        cust = await machine.ainjector(FilesystemCustomization, machine)
        async with cust.customization_context:
            pki_dir = cust.path.joinpath(self.pki_access_dir or self.pki_dir)
            pki_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            await cust.run_command(
                'entanglement-pki',
                '--force',
                '--pki-dir=/'+str(self.pki_dir),
                '--ca-name='+self.ca_name,
                dns_name)
            return pki_dir.joinpath(dns_name+'.key').read_text(), \
                pki_dir.joinpath(dns_name+'.pem').read_text()

    async def trust_store(self):
        return await self.ainjector(
            SimpleTrustStore,
            'entanglement_trust',
            dict(
                entanglement_ca=await self.ca_cert_pem()))

    async def certificates(self):
        async with self.machine.filesystem_access() as path:
            pki_path = path.joinpath(self.pki_access_dir or self.pki_dir)
            for pem in pki_dir.glob('*.pem'):
                yield pem.read_text()

class EntanglementCertificateAuthority(ContainedEntanglementPkiManager, MachineModel, template=True):
    class ca_customization(FilesystemCustomization):

        description = "Set up entanglement-pki"
        entanglement_pki_role = ansible_role_task('install-entanglement-pki')


__all__ += ['EntanglementCertificateAuthority']

@inject(
    ainjector=AsyncInjector)
async def find_dns_zone(domain:str, *, ainjector):
    '''
    Find whether there is a zone that encompasses *domain*.
    '''
    if domain[-1] == '.':
        domain = domain[:-1]
    while domain:
        try:
            zone = await ainjector.get_instance_async(InjectionKey(DnsZone, name=domain))
            return zone
        except KeyError:
            _, sep, domain = domain.partition('.')
    raise LookupError('No DNS zone registered in injector hierarchy')

def safe_tag(tag:str)->str:
    '''
    Return a version of a tag safe for use as a filename
    '''
    return re.sub(r'[^a-zA-Z0-9\._-]', '_', tag)

class Le2136PkiManager(PkiManager):

    '''
    An abstract base class that runs LetsEncrypt (certbot) in DNS RFC2136 mode, allowing it to update a DNS zone using dns-tsig and use that to satisfy DNS-01 challenges for a certificate.

    This class leaves a few details of interfacing with certbot and retrieving results up to subclasses.

    '''

    certbot_production_certificates:bool = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.certbot_lock = asyncio.Lock()
        self.certbot_tags_by_hostname = {}
        
    key_name_re = re.compile(r'key\s+"([^"]+)"')
    algorithm_re = re.compile(r'algorithm\s+([-a-zA-Z0-9]+);')
    secret_re = re.compile(r'secret\s+"([^"]+)"')
    
    def bind9_tsig_to_certbot(self, tsig_key, *, server='127.0.0.1', port=53):
        '''
        Takes as input a bind9  tsig key statement and returns a rfc2136 credentials INI.
        :param server: the DNS server to send queries to.
        '''
        if match := self.key_name_re.search(tsig_key):
            key_name = match.group(1)
        else:
            raise ValueError('Unable to find key name')
        if match := self.algorithm_re.search(tsig_key):
            algorithm = match.group(1)
            # certbot requires algorithm to be upper case and silently
            # falls back to md5 if the algorithm is unknown.
            algorithm = algorithm.upper()
        else:
            raise ValueError('Unable to find algorthim')
        if match := self.secret_re.search(tsig_key):
            secret = match.group(1)
        else:
            raise ValueError('Unable to find secret')
        return f'''
dns_rfc2136_name = {key_name}
dns_rfc2136_secret = {secret}
dns_rfc2136_algorithm = {algorithm}
dns_rfc2136_server = {server}
dns_rfc2136_port = {port}
'''

    async def get_rfc2136_credentials(self, zone):
        '''
        called by :meth:`run_certbot` to generate a dns-rfc2136-credentials file.
        '''
        key_path = zone.key_path
        try:
            server = zone.zone_info.update_server
            server = await resolve_deferred(zone.ainjector, server, args=dict(zone=zone))
        except AttributeError:
            server = '127.0.0.1'
        return self.bind9_tsig_to_certbot(key_path.read_text(), server=server)

    async def issue_credentials(self, hostname:str, tag:str):
        current_tags = self.certbot_tags_by_hostname.setdefault(hostname, set())
        if tag in current_tags:
            raise RuntimeError(f'{tag} not unique for {hostname}')
        current_tags.add(tag)
        zone_obj = await self.ainjector(find_dns_zone, hostname)
        async with self.certbot_lock:
            cert_name = safe_tag(hostname)+':'+safe_tag(tag)
            await  self.run_certbot(
                zone_obj,
                'certonly',
                '--cert-name', cert_name,
                '--dns-rfc2136',
                '-d', hostname,
                '--no-autorenew'
            )
        async with self.certbot_access() as path:
            key = path/cert_name/'privkey.pem'
            chain = path/cert_name/'fullchain.pem'
            return key.read_text(), chain.read_text()

    async def trust_store(self):
        return await self.ainjector(
            carthage.pki.LetsencryptTrustStore,
            production=self.certbot_production_certificates
            )

    async def certificates(self):
        async with self.certbot_access() as path:
            for cert in path.glob('*:*/fullchain.pem'):
                yield cert.read_text()
                
    async def certbot_access(self):
        '''
        Abstract method that provides access to the letsencrypt live (or other configured directory) for the certbot instance.
        Works like :meth:`carthage.machine.Machine.filesystem_access` except is relative to the letsencrypt live directory.
        '''
        raise NotImplementedError

    async def run_certbot(self, zone:DnsZone, *args):
        '''
        Run certbot with the given arguments.
        This is responsible for calling self.get_rfc2136_credentials and saving that to a file certbot can read, and including a --dns-rfc2136-credentials option.

        :param zone: The DNS zone in which the certificates live.
        '''
        raise NotImplementedError
    
__all__ += ['Le2136PkiManager']

class InstallCertbot2136Customization(FilesystemCustomization):

    @setup_task("Install certbot")
    async def install_certbot(self):
        await self.run_command(
            'apt', '-y', 'install',
            'python3-certbot-dns-rfc2136',
            'certbot')

class Le2136PkiManagerMachineMixin(Machine, Le2136PkiManager):

    '''
    Run letsencrypt on a :class:`carthage.machine.Machine`
    '''

    # In case we are an OCI container, be interactive so we stay
    # running even with /bin/sh as a command.
    oci_interactive = True

    @memoproperty
    def certbot_production_certificates(self):
        '''Should we use production or staging certificates: true for production
        '''
        try:
            return self.model.certbot_production_certificates
        except AttributeError:
            return True
        
    async def run_certbot(self, zone:DnsZone, *args):
        if not self.model.certbot_email:
            raise RuntimeError('certbot email not specified')
        test_argument = []
        if not self.certbot_production_certificates:
            test_argument.append('--test-cert')
        async with self.machine_running(), self.filesystem_access() as path:
            credentials = await self.get_rfc2136_credentials(zone)
            credentials_path = path/'dns.credentials'
            credentials_path.touch()
            credentials_path.chmod(0o600)
            credentials_path.write_text(credentials)
            await self.run_command(
                'certbot',
                '-n',
                '--agree-tos',
                '-m', self.model.certbot_email,
                *test_argument,
                *args,
                '--dns-rfc2136-credentials=/dns.credentials')

    @contextlib.asynccontextmanager
    async def certbot_access(self):
        async with self.filesystem_access() as path:
            pki_dir =path.joinpath(self.model.pki_access_dir or "")
            yield pki_dir/'etc/letsencrypt/live'

class Le2136PkiManagerModel(MachineModel, template=True):

    '''
    typical usage::

        class pki(Le2136PkiManagerModel):
            certbot_email = 'email.address@domain'
            certbot_production_certificates = False
            #In this scope, PkiManager is provided, but generally it
            # needs to be provided more broadly
        add_provider(InjectionKey(PkiManager, _globally_unique=True),
            injector_xref(InjectionKey('pki'), InjectionKey(PkiManager)),
            propagate_up=True)

    '''

    certbot_email:str = ""
    certbot_production_certificates:bool = True
        #: If non-none, access letsencrypt directory via this (potentially absolute) path.  If ca is a container, and pki_dir is mounted from the host, pki_access_dir may need to be set; 'etc/letsencrypt/live' is appended.
    pki_access_dir = None

    add_provider(InjectionKey(MachineMixin, name='le_pki'),
                 dependency_quote(Le2136PkiManagerMachineMixin))
    add_provider(InjectionKey(PkiManager), injector_access(InjectionKey(Machine)))

    install_certbot = InstallCertbot2136Customization
    

__all__ += ['Le2136PkiManagerModel']
