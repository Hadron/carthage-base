# Copyright (C) 2018, 2019, 2020, 2021, 2022, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
from pathlib import Path

from carthage import *
from carthage.modeling import *
from carthage.ansible import ansible_role_task
import carthage.setup_tasks

__all__ = []

class CertificateAuthority(InjectableModel):

    async def ca_cert_pem(self):
        raise NotImplementedError

    async def certify(self, dns_name):
        raise NotImplementedError

__all__ += ['CertificateAuthority']
class CertificateInstallationTask(carthage.setup_tasks.TaskWrapperBase):

    key_dir: Path
    ca_path: Path
    cert_dir: Path
    stem: str

    def __init__(self, *,
                 ca_path, cert_dir, key_dir,
                 stem=None,
                 **kwargs):
        super().__init__(**kwargs)
        self.ca_path = relative_path(ca_path)
        self.cert_dir = relative_path(cert_dir)
        self.key_dir = relative_path(key_dir)
        self.stem = stem

    @property
    def cert_fn(self):
        return self.cert_dir/f'{self.stem}'

    @property
    def key_fn(self):
        return self.key_dir/self.stem
    
        
    @inject(ca=InjectionKey(CertificateAuthority, _ready=True))
    async def func(self, instance, ca):
        dns_name = instance.name
        carthage.utils.validate_shell_safe(dns_name)
        cust = await self.ainjector(FilesystemCustomization, inst)
        async with cust.customization_context:
            key, cert = await ca.certify(dns_name)
            if not self.stem: self.stem = f'{dns_name}.pem'
            cert_dir = cust.path/self.cert_dir
            key_dir = cust.path/self.key_dir
            key_dir.mkdir(mode=0o700, exist_ok=True, parents=True)
            cert_dir.mkdir(mode=0o755, exist_ok=True, parents=True)
            cust.path.joinpath(self.key_fn).write_text(key)
            cust.path.joinpath(self.cert_fn).write_text(cert)

    async def check_completed_func(self, instance):
        try:
            cust = await self.ainjector(FilesystemCustomization, instance)
            async with cust.customization_context:
                if not self.stem: self.stem = f'{instance.name}.pem'
                stat = cust.path.joinpath(self.cert_fn).stat()
                return st.st_mtime
        except FileNotFoundError: return False
        except Exception:
            #Also return False, although perhaps we should log debugging info.  This can be a normal condition if a machine does not yet exist.
            return False
        
__all__ += ['CertificateInstallationTask']


class EntanglementCertificateAuthority(CertificateAuthority, MachineModel, template=True):

    class ca_customization(FilesystemCustomization):

        description = "Set up entanglement-pki"
        entanglement_pki_role = ansible_role_task('install-entanglement-pki')

    pki_dir = '/etc/pki'
    ca_name = 'Root CA'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pki_dir = relative_path(self.__class__.pki_dir)
    async def ca_cert_pem(self):
        machine = self.machine
        await machine.async_become_ready()
        cust = await machine.ainjector(FilesystemCustomization, machine)
        async with cust.customization_context:
            pki_dir = cust.path.joinpath(self.pki_dir)
            try: return pki_dir.joinpath('ca.pem').read_text()
            except FileNotFoundError:
                await cust.run_command(
                    'entanglement-pki',
                    '--pki-dir='+str(self.pki_dir),
                    '--ca-name='+self.ca_name)
                return pki_dir.joinpath('ca.pem').read_text()

    async def certify(self, dns_name):
        machine = self.machine
        await machine.async_become_ready()
        cust = await machine.ainjector(FilesystemCustomization, machine)
        async with cust.customization_context:
            pki_dir = cust.path/self.pki_dir
            pki_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            await cust.run_command(
                'entanglement-pki',
                '--force',
                '--pki-dir='+str(self.pki_dir),
                '--ca-name='+self.ca_name,
                dns_name)
            return pki_dir.joinpath(dns_name+'.key').read_bytes(), \
                pki_dir.joinpath(dns_name+'.pem').read_bytes()

__all__ += ['EntanglementCertificateAuthority']
