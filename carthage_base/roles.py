# Copyright (C) 2018, 2019, 2020, 2021, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
from carthage import *
from carthage.modeling import *
from pathlib import Path

__all__ = []

class DhcpRole(MachineModel, template = True):

    override_dependencies = True

    dnsmasq_conf = mako_task("dhcp-dnsmasq.conf",
                             output = "etc/dnsmasq.d/dhcp.conf",
                             model = InjectionKey(MachineModel))

    class dhcp_customization(MachineCustomization):

        @setup_task("install software")
        async def install_software(self):
            await self.ssh("systemctl disable --now systemd-resolved", _bg = True, _bg_exc = False)
            await self.ssh("apt -y install dnsmasq",
                           _bg = True,
                           _bg_exc = False)
            async with self.filesystem_access() as path:
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
            
