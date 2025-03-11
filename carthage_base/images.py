# Copyright (C) 2018, 2019, 2020, 2021, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
import shutil
from carthage import *
from carthage.modeling import *
import carthage
from carthage.debian import *
from carthage.vm import vm_image_key
from carthage.systemd import SystemdNetworkModelMixin
from pathlib import Path
from carthage import debian

__all__ = []

class LinuxMachine(MachineModel, SystemdNetworkModelMixin, template=True):

    @memoproperty
    def ip_address(self):
        #first do we have a network link with a static address?
        for l in self.network_links.values():
            if getattr(l, 'local_type', None) == 'none':
                #That is the string none not None meaning physical
                continue
            v4 = l.merged_v4_config
            if v4 and v4.address:
                return str(v4.address)
        # otherwise let's try the hostname
        return self.name
        

__all__ += ['LinuxMachine']

class DebianImageCustomization(ContainerCustomization):
    description = "Customizations for Debian Images"

    install_packages = install_stage1_packages_task([
        'git', 'emacs-nox', 'ansible', 'rsync',
        'libnss-resolve',
        'mailutils-'])

    @setup_task("Use systemd-resolved for name service")
    def use_systemd_resolved(self):
        root = Path(self.path)
        if not root.joinpath("usr/bin/resolvectl").exists():
            self.container_command('apt', '-y', 'install', 'systemd-resolved')
        try: root.joinpath("etc/resolv.conf").unlink()
        except FileNotFoundError: pass
        shutil.copy(root/"usr/lib/systemd/resolv.conf", root/"etc")
        
class DebianMirrorTracker(FilesystemCustomization):

    description="Track updates to configured mirror"
    runas_user = 'root'

    @setup_task("Update mirror")
    async def update_mirror_tracker(self):
        config = self.injector(ConfigLayout)
        mirror = config.debian
        debian.update_mirror(self.path, mirror.mirror, mirror.distribution, mirror.include_security)
        await self.run_command('apt', 'update')

    @update_mirror_tracker.hash()
    def update_mirror_tracker(self):
        config = self.injector(ConfigLayout)
        mirror = config.debian
        return str({
            'mirror': mirror.mirror,
            'distribution':mirror.distribution,
            'include_security':mirror.include_security,
            })

__all__ += ['DebianMirrorTracker']

class DebianImage(DebianContainerImage):
    ssh_authorization = customization_task(carthage.image.SshAuthorizedKeyCustomizations)
    debian_image_customizations = customization_task(DebianImageCustomization)
    mirror_tracking = customization_task(DebianMirrorTracker)
    
__all__ += ['DebianImage']

         

@provides(vm_image_key)
@inject(ainjector = AsyncInjector,
        image = DebianImage)
async def debian_vm_image(ainjector, image):
    return await ainjector(
        debian_container_to_vm,
        image, f"{image.name}.raw",
        "10G",
        classes = "+SERIAL,CLOUD_INIT,GROW,OPENROOT")

__all__ += ['debian_vm_image']

