# Copyright (C) 2025, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

'''

This module provides classes and functions to make it easier to run tests against layouts typically on a privileged Podman container, or a podman container with access to an imported podman socket.

'''

from carthage import *
from carthage.network import V4Config
from carthage.modeling import *
from carthage.console import CarthageRunnerCommand
import carthage.podman as carthage_podman
from .proxy import ProxyConfig

@provides(InjectionKey('test_network', _globally_unique=True))
class test_network(NetworkModel):
    name = "test_network"
    v4_config = V4Config(network="10.20.20.0/24", pool=('10.20.20.10', '10.20.20.100'),
                         dhcp=False)

class test_network_config(NetworkConfigModel):
            add('eth0', net=InjectionKey('test_network'), mac=None)

class DumpAddressesCommand(CarthageRunnerCommand):

    name = 'dump-addresses'

    async def run(self, args):
        layout = await self.ainjector.get_instance_async(CarthageLayout)
        networks = set()
        for model in await layout.all_models():
            try:
                network_links = model.network_links
            except AttributeError: continue
            for link in network_links.values():
                if link.net not in networks:
                    link.net.assign_addresses()
                    networks.add(link.net)
                if link.merged_v4_config and link.merged_v4_config.address:
                    print(f'{link.merged_v4_config.address}\t{link.dns_name or model.name}')

    def setup_subparser(self, subparser):
        pass
    
                    

class ContainerizedCiLayout(CarthageLayout):
    add_provider(machine_implementation_key, dependency_quote(carthage_podman.PodmanContainer))
    add_provider(carthage_podman.podman_container_host, carthage_podman.LocalPodmanContainerHost)

    test_network = test_network
    add_provider(InjectionKey(NetworkConfig), test_network_config)
    add_provider(DumpAddressesCommand)
    add_provider(ProxyConfig)
    
    
