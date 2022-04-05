# Copyright (C) 2018, 2019, 2020, 2021, 2022, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
import os.path
from pathlib import Path
import carthage
import carthage.systemd
from carthage import *
from carthage.modeling import *
from carthage.ssh import SshKey
from carthage.ansible import *
from carthage.sonic import SonicNetworkModelMixin

__all__ = []

class DhcpRole(MachineModel, template = True):

    override_dependencies = True

    dnsmasq_conf = mako_task("dhcp-dnsmasq.conf",
                             output = "etc/dnsmasq.d/dhcp.conf",
                             model = InjectionKey(MachineModel))

    class dhcp_customization(MachineCustomization):

        @setup_task("install software")
        async def install_software(self):
            await self.ssh("apt -y install dnsmasq",
                           _bg = True,
                           _bg_exc = False)
            await self.ssh("systemctl disable --now systemd-resolved", _bg = True, _bg_exc = False)
            async with self.filesystem_access() as path:
                try: Path(path).joinpath("etc/resolv.conf").unlink()
                except FileNotFoundError: pass
                with                                     Path(path).joinpath("etc/resolv.conf").open("wt") as f:
                    f.write("nameserver 127.0.0.1\n")



        install_mako = install_mako_task('model')

        @setup_task("restart dnsmasq")
        async def restart_dnsmasq(self):
            if not self.running: return
            await self.ssh("systemctl restart dnsmasq",
                           _bg = True,
                           _bg_exc = False)

__all__ += ['DhcpRole']
            
class CarthageServerRole(MachineModel, template = True):

    project_destination = "/"

    #: If true (the default), then checkout_dir is synchronized to the destination
    copy_in_checkouts = True

    #:if True (the default), keep track of the git hashes of copied trees and copy again on change.
    carthage_role_track_git_changes = True
    
    class customize_for_carthage(FilesystemCustomization):

        libvirt_server_role = ansible_role_task('libvirt-server')

        @setup_task("Copy in carthage and layout")
        @inject(ainjector=AsyncInjector,
                ssh_key=SshKey,
                config=ConfigLayout)
        async def copy_in_carthage(self, ainjector, config, ssh_key):
            host = self.host
            project_destination = Path(host.model.project_destination)
            await self.run_command("mkdir", "-p", str(project_destination), _bg=True, _bg_exc=False)
            await self.run_command('apt', 'update', _bg=True, _bg_exc=False)
            await self.run_command("apt", *'-y install rsync sshfs'.split(),
                           _bg=True, _bg_exc=False)
            await self.run_command("mkdir", "-p", config.checkout_dir, _bg=True, _bg_exc=False)
            await ainjector(
                rsync_git_tree,
                os.path.dirname(carthage.__file__),
                RsyncPath(host, project_destination/"carthage"))
            if hasattr(host.model, 'layout_source'):
                await ainjector(
                    rsync_git_tree,
                    host.model.layout_source,
                    RsyncPath(host, project_destination/host.model.layout_destination))
            if host.model.copy_in_checkouts:
                checkout_dir = config.checkout_dir
                await ainjector(
                    ssh_key.rsync,
                    "-a",
                    "--delete",
                    f'{checkout_dir}/',
                    RsyncPath(host, checkout_dir))

        @copy_in_carthage.hash()
        def copy_in_carthage(self):
            if not self.model.carthage_role_track_git_changes: return ""
            hashes = []
            hashes.append(git_tree_hash(os.path.dirname(carthage.__file__)))
            try:
                hashes.append(git_tree_hash(self.model.layout_source))
            except AttributeError: pass
            return str(hashes)
        

__all__ += ['CarthageServerRole']

@inject(authorized_keys=carthage.ssh.AuthorizedKeysFile)
class SonicMachineMixin(Machine, SetupTaskMixin):

        
    # We cannot just use a CustomizationTask in the model because we
    # need to force this role to be very early
    
    sonic_role = ansible_role_task(
        "sonic_config",
        before=carthage.systemd.SystemdNetworkInstallMixin.generate_config_dependency)
    
class SonicRole(SonicNetworkModelMixin, MachineModel, template=True):

    add_provider(InjectionKey(MachineMixin, name="sonic"), dependency_quote(SonicMachineMixin))

__all__ += ['SonicRole']
