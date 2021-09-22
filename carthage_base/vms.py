# Copyright (C) 2018, 2019, 2020, 2021, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
from carthage import *
from carthage.modeling import *
from carthage.files import git_checkout_task
from carthage.ansible import *

from .images import *
from .hosted import *
from carthage.vm import vm_image

__all__ = []

class CarthageMirrorsVm(LinuxMachine):

    add_provider(machine_implementation_key, HostedVm)
    add_provider(vm_image, debian_vm_image, transclusion_overrides=True)
    add_provider(DebianImage, transclusion_overrides=True)
        

    cloud_init = True
    name = "carthage-mirrors"

    checkout_carthage_mirrors = git_checkout_task(injector_access("carthage_mirrors_url"), 'carthage-mirrors')

    class customize(MachineCustomization):

        @setup_task("Sync in git dependencies")
        async def sync_git(self):
            await self.ainjector(
                rsync_git_tree,
                self.injector(self.model.checkout_carthage_mirrors.repo_path),
                RsyncPath(self.host, "/carthage-mirrors"))


        @inject(model = MachineModel)
        dedf mirrors_vars(model):
        return dict(
            storage_path = model.storage_nfs_path,
            )

        carthage_mirrors_role = ansible_role_task('carthage-mirrors', vars=mirrors_vars)

__all__ += ['CarthageMirrorsVm']
