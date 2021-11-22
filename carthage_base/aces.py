# Copyright (C) 2018, 2019, 2020, 2021, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.


# This file depends on hadron-operations which is not public.  Make
# sure that __init__.py does not call in this file.  IF you are going
# to use this file, make sure your config includes hadron-operations *
# otherwise hadron.carthage will not exist.

import os

from carthage import *
from carthage import sh
from carthage.modeling import *
from carthage.ansible import *
from carthage.utils import memoproperty
from hadron.carthage.tasks import *
from hadron.carthage.images import HadronImageMixin
from pathlib import Path

from .images import DebianImage

@inject(config = ConfigLayout)
class UsefulVars(AnsibleGroupPlugin):

    name = "hadron_integration_vars"

    async def group_info(self):
        config = self.config
        import urllib.parse
        url = urllib.parse.urlparse(config.debian.mirror)
        vars = {
            'hadron_vault_addr': 'https://vault.hadronindustries.com:8200/'}
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
        output_dir = Path(self.config_layout.output_dir)
        os.makedirs(output_dir, exist_ok=True)
        output_dir.joinpath("vpn_ca.pem").write_text(aces_root.read_text())

    @setup_task("make download")
    async def make_download(self):
        repo_path = Path(self.config_layout.checkout_dir)/"hadron-operations"
        stamp_path = self.stamp_path
        os.makedirs(self.stamp_path, exist_ok=True)
        try: stamp_path.joinpath("packages").symlink_to(repo_path/"ansible/packages")
        except FileExistsError: pass
        try: stamp_path.joinpath('output').symlink_to(repo_path/"ansible/output")
        except FileExistsError: pass
        try:         stamp_path.joinpath("output").symlink_to(self.config_layout.output_dir)
        except FileExistsError: pass
        os.makedirs(repo_path.joinpath("ansible/packages"), exist_ok=True)
        await sh.make(
            "download",
            _bg = True,
            _bg_exc = False,
            _cwd  = repo_path)
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
        slot.release = getattr(self, 'hadron_release', "bullseye")
        slot.track = getattr(self, 'hadron_track', "snapshot")
        return slot

    hadron_role = "debian"

    @memoproperty
    def role_names(self):
        return (self.hadron_role,)
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

class AcesCustomizations( HadronImageMixin):

    @setup_task("re-enable systemd-networkd and systemd-resolved")
    async def enable_systemd_services(self):
        await self.container_command(
            "/bin/systemctl", "enable",
            "systemd-networkd", "systemd-networkd.socket",
            "systemd-resolved")
        try:
            await self.container_command("/usr/bin/apt", "-y", "purge", "haveged")
        except: pass


class AcesBaseImage(DebianImage):

    '''A base image set up to access hadron proprietary packages with minimal Hadron packages installed.
'''

    name = "base-aces"

    aces_customizations = customization_task(AcesCustomizations)

__all__ += ['AcesBaseImage']
