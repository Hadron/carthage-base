from carthage import *
from carthage.modeling import *
import carthage
from carthage.debian import *
from carthage.vm import vm_image
from carthage.systemd import SystemdNetworkModelMixin

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

class DebianImage(DebianContainerImage):
    ssh_authorization = customization_task(carthage.image.SshAuthorizedKeyCustomizations)
    install_packages = wrap_container_customization(install_stage1_packages_task(['git', 'emacs-nox', 'ansible', 'rsync', 'mailutils-']))

__all__ += ['DebianImage']

@provides(vm_image)
@inject(ainjector = AsyncInjector,
        image = DebianImage)
async def debian_vm_image(ainjector, image):
    return await ainjector(
        debian_container_to_vm,
        image, "debian-base.raw",
        "10G",
        classes = "+SERIAL,CLOUD_INIT,OPENROOT")

__all__ += ['debian_vm_image']
