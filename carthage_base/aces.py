# Copyright (C) 2018, 2019, 2020, 2021, 2025, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.


# This file depends on hadron-operations which is not public.  Make
# sure that __init__.py does not call in this file.  If you are going
# to use this file, make sure your config includes hadron-operations *
# otherwise hadron.carthage will not exist.

import os

from carthage import *
from carthage import sh
from carthage.modeling import *
from carthage.podman.modeling import *
from carthage.ansible import *
from carthage.utils import memoproperty
from carthage.image import SshAuthorizedKeyCustomizations
from hadron.carthage.tasks import *
from pathlib import Path

from .images import DebianImage

@inject(injector=Injector)
class UsefulVars(AnsibleGroupPlugin):

    name = "hadron_integration_vars"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.config_layout = self.injector(ConfigLayout)
        self.packages_path = Path(self.config_layout.state_dir)/'hadron_packages'

    async def group_info(self):
        config = self.config_layout
        import urllib.parse
        url = urllib.parse.urlparse(config.debian.mirror)
        vars = {
            
            'hadron_vault_addr': 'https://vault.hadronindustries.com:8200/',
            'packagedir': str(self.packages_path),
        }
        if url.path =="/debian":
            vars['debian_mirror'] = url.netloc
        
        return dict(all = dict(vars = vars))

    async def groups_for(self, m):
        return []

class AcesIntegration(ModelTasks):


    @setup_task("Handle Certificates")
    def handle_certificates(self):
        aces_root = Path("/usr/share/ca-certificates/aces/hadron_vault_root.crt")
        if not aces_root.exists(): raise SkipSetupTask
        cache_dir = Path(self.config_layout.cache_dir)
        os.makedirs(cache_dir, exist_ok=True)
        cache_dir.joinpath("vpn_ca.pem").write_text(aces_root.read_text())

    @setup_task("make download")
    async def make_download(self):
        repo_path = Path(self.config_layout.checkout_dir)/"hadron-operations"
        packages_path = repo_path/"ansible/packages"
        packages_path.mkdir(parents=True, exist_ok=False)
        stamp_path = self.stamp_path
        packages_path = Path(self.config_layout.state_dir)/'hadron_packages'
        # try symlink ansible/packages in the repo to somewhere that will be preserved if the checkout is cleared so packages are preserved.
        try: (repo_path/"ansible/packages").symlink_to(packages_path)
        except FileExistsError: pass
        # But we need to link whatever the repo is using into what
        # will become the hadron config dir because that directory
        # goes into pkgdir in the ansible inventory based on what the
        # hosts plugin from h-o sets up.
        try: stamp_path.joinpath('packages').symlink_to(repo_path/'ansible/packages')
        except FileExistsError: pass
        try: stamp_path.joinpath('output').symlink_to(repo_path/"ansible/output")
        except FileExistsError: pass
        try:         stamp_path.joinpath("output").symlink_to(self.config_layout.cache_dir)
        except FileExistsError: pass
        os.makedirs(repo_path.joinpath("ansible/packages"), exist_ok=True)
        try:
            await sh.make(
                "download",
                _bg = True,
                _bg_exc = False,
                _cwd  = str(repo_path))
        except sh.ErrorReturnCode:
            if packages_path.glob("*.deb"):
                pass
            else:
                raise
        return

    async def async_ready(self):
        await self.run_setup_tasks()
        base_injector.add_provider(UsefulVars)
        parent_injector = self.injector.parent_injector
        # at this point we should be able to import hadron stuff
        import hadron.carthage
        import carthage.ansible
        parent_injector.add_provider(InjectionKey(carthage.ansible.AnsibleHostPlugin, name = "hadron"),
                                     hadron.carthage.ansible.HadronHostPlugin)
        parent_injector.add_provider(hadron.inventory.config.generator.ConfigCache)
        parent_injector.add_provider(hadron.inventory.config.generator.hadron_config_dir_key, self.stamp_path)
        return await AsyncInjectable.async_ready(self)

@inject(
    aces_integration = InjectionKey(AcesIntegration.our_key(), _ready=True))
class AcesMachine(MachineModel, template = True):

    @property
    def this_slot(self):
        import hadron.carthage
        try: self.network.domain
        except AttributeError: self.network.domain = self.injector.get_instance(InjectionKey("domain"))
        slot =  hadron.carthage.fake_slot_for_model(self, netid = 1, role =self.hadron_role)
        slot.os = getattr(self,'hadron_os',"Debian")
        slot.release = getattr(self, 'hadron_release', "bookworm")
        slot.track = getattr(self, 'hadron_track', "snapshot")
        return slot

    hadron_role = "debian"

    @memoproperty
    def role_names(self):
        return (self.hadron_role,)

    def __init_subclass__(cls, **kwargs):
        mro = cls.__mro__
        aces_index = mro.index(AcesMachine)
        from . import roles
        for r_name in roles.__all__:
            r = getattr(roles, r_name)
            try: r_index = mro.index(r)
            except ValueError: continue
            if r_index > aces_index:
                raise TypeError(f'AcesMachine should come later in the base class list than any Carthage Role so that the machine is converted to ACES before roles are applied.')
        super().__init_subclass__(**kwargs)
        
    class hadron_distribution_customization(MachineCustomization):
        aces_distribution = ansible_role_task(dict(
            name = "aces-base",
            tasks_from = 'distribution.yml'))

        @setup_task("Remove debian.list")
        async def remove_debian_list(self):
            async with self.filesystem_access() as root:
                try: os.unlink(Path(root)/"etc/apt/sources.list.d/debian.list")
                except FileNotFoundError: pass


__all__ = ['AcesIntegration', 'AcesMachine']

class AcesCustomizations( FilesystemCustomization):
    description = 'Enable ACES software'

    @setup_task('Install basic dependencies')
    async def install_dependencies(self):
        await self.run_command(
            'apt',
            'update')
        await self.run_command(
            'apt', '-y', 'install',
            'python3',
            'rsync',
            'systemd',
            )

    aces_distribution = aces_distribution_task(use_config=True)
    


@inject(base_image=None)
class AcesPodmanImage(PodmanImageModel):

    base_image = 'debian:trixie'
    oci_image_tag = 'localhost/aces:latest'
    oci_image_command = ['/lib/systemd/systemd']
    hadron_os = 'Debian'
    hadron_release = 'trixie'
    hadron_track = 'unstable'
    
    aces_customizations = AcesCustomizations
    authorized_keys = SshAuthorizedKeyCustomizations

__all__ += ['AcesPodmanImage']

class AcesBaseImage(DebianImage):

    '''A base image set up to access hadron proprietary packages with minimal Hadron packages installed.
'''

    name = "base-aces"

    aces_customizations = customization_task(AcesCustomizations)

__all__ += ['AcesBaseImage']
