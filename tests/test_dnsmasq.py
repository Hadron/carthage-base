# Copyright (C) 2026, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

"""Tests for the DnsmasqRole dhcp-dnsmasq.conf generation.

One shared layout (dnsmasq_layout) models a dhcp relay between two
networks:

  router        (DnsmasqRole)  eth0 on main_net (10.0.0.2)
                                eth1 on relay_net (10.1.0.1)
                relays relay_net to 10.0.0.1
  dhcp_server   (DnsmasqRole)  eth0 on main_net (10.0.0.1)
                serves main_net directly and relay_net via relay

The dhcp server (10.0.0.1) is also the global DNS server for both
networks (network-level v4_config.dns_servers), while its own link
overrides dns_servers so its dnsmasq forwards to a separate upstream.

Machines are never instantiated; the tests only generate() the layout
and inspect the rendered config.
"""

from pathlib import Path

from carthage import InjectionKey
from carthage.modeling import (CarthageLayout, NetworkModel,
                               NetworkConfigModel, MachineModel)
from carthage.network import V4Config
from carthage.pytest import async_test, load_test_plugin

UPSTREAM = '8.8.8.8'
GLOBAL_DNS = '10.0.0.1'

plugin = load_test_plugin(__file__, '..')
carthage_base = plugin.package
DnsmasqRole = carthage_base.DnsmasqRole


class dnsmasq_layout(CarthageLayout):
    domain = 'dnsmasq.test'

    class main_net(NetworkModel):
        name = 'main'
        # The dhcp server (10.0.0.1) is the global DNS server.
        v4_config = V4Config(
            network='10.0.0.0/24',
            gateway='10.0.0.1',
            dns_servers=(GLOBAL_DNS,),
        )

    class relay_net(NetworkModel):
        name = 'relayed'
        v4_config = V4Config(
            network='10.1.0.0/24',
            gateway='10.1.0.1',
            dns_servers=(GLOBAL_DNS,),
            dhcp_ranges=[('10.1.0.10', '10.1.0.50')],
        )

    class router(DnsmasqRole):
        name = 'router'
        relay_server = GLOBAL_DNS
        relay_networks = (InjectionKey('relay_net'),)

        class net_config(NetworkConfigModel):
            add('eth0', mac=None, net=InjectionKey('main_net'),
                v4_config=V4Config(address='10.0.0.2'))
            add('eth1', mac=None, net=InjectionKey('relay_net'),
                v4_config=V4Config(address='10.1.0.1'))

    class dhcp_server(DnsmasqRole):
        name = 'dhcp'
        served_networks = (InjectionKey('relay_net'),)

        class net_config(NetworkConfigModel):
            # The server's own link overrides dns_servers so dnsmasq
            # forwards to a separate upstream rather than itself.
            add('eth0', mac=None, net=InjectionKey('main_net'),
                v4_config=V4Config(address=GLOBAL_DNS,
                                   dns_servers=(UPSTREAM,)))

    class host_main(MachineModel):
        name = 'host-main'

        class net_config(NetworkConfigModel):
            add('eth0', mac='aa:bb:cc:00:00:01',
                net=InjectionKey('main_net'),
                v4_config=V4Config(dhcp=True))

    class host_relay(MachineModel):
        name = 'host-relay'

        class net_config(NetworkConfigModel):
            add('eth0', mac='aa:bb:cc:00:00:02',
                net=InjectionKey('relay_net'),
                v4_config=V4Config(dhcp=True))


async def generated(ainjector):
    '''Instantiate the shared layout and generate() it (render all
    mako templates) without instantiating any machines.'''
    ainjector.add_provider(dnsmasq_layout)
    layout = await ainjector.get_instance_async(CarthageLayout)
    await layout.generate()
    return layout


def dnsmasq_conf(model):
    path = Path(model.stamp_path) / 'etc/dnsmasq.d/dhcp.conf'
    assert path.exists(), f'dnsmasq config not rendered: {path}'
    return path.read_text()


@async_test
async def test_router_relay_config(ainjector):
    layout = await generated(ainjector)
    conf = dnsmasq_conf(layout.router)
    # Relays the relayed network via its local address on that network,
    # to the dhcp server.
    assert 'dhcp-relay=10.1.0.1,10.0.0.1' in conf
    # A pure relay serves no ranges itself.
    assert 'dhcp-range' not in conf


@async_test
async def test_dhcp_server_serves_relayed_network(ainjector):
    layout = await generated(ainjector)
    conf = dnsmasq_conf(layout.dhcp_server)
    # The relayed network's range carries an explicit netmask; the
    # attached network's does not.
    assert 'dhcp-range=set:relayed,10.1.0.10,10.1.0.50,255.255.255.0,10h' in conf
    assert 'dhcp-range=set:eth0,10.0.0.0,static' in conf
    # Gateway option for the relayed network.
    assert 'dhcp-option=tag:relayed,option:router,10.1.0.1' in conf


@async_test
async def test_global_dns_with_separate_upstream(ainjector):
    layout = await generated(ainjector)
    conf = dnsmasq_conf(layout.dhcp_server)

    # The dhcp server is the global DNS server for both networks.
    assert layout.main_net.v4_config.dns_servers == (GLOBAL_DNS,)
    assert layout.relay_net.v4_config.dns_servers == (GLOBAL_DNS,)

    # The router's links inherit the global DNS server from their
    # network.
    router = layout.router
    for link in router.network_links.values():
        assert list(link.merged_v4_config.dns_servers) == [GLOBAL_DNS]

    # The server's own link overrides it with a separate upstream, so
    # its dnsmasq does not forward to itself.
    server = layout.dhcp_server
    (eth0,) = (l for l in server.network_links.values()
               if l.net.name == 'main')
    assert list(eth0.merged_v4_config.dns_servers) == [UPSTREAM]

    # The rendered config reflects that: the only server line is the
    # upstream, never the server itself.
    assert f'server={UPSTREAM}' in conf
    assert f'server={GLOBAL_DNS}' not in conf


@async_test
async def test_dhcp_host_lines_are_tagged(ainjector):
    layout = await generated(ainjector)
    conf = dnsmasq_conf(layout.dhcp_server)
    # A client on the attached (main) network is tagged by the
    # server's interface on that network.
    assert ('dhcp-host=set:eth0,aa:bb:cc:00:00:01,'
            'host-main.dnsmasq.test,18h') in conf
    # A client on the relayed network is tagged by the network name,
    # which is the tag dnsmasq uses for its relayed range.
    assert ('dhcp-host=set:relayed,aa:bb:cc:00:00:02,'
            'host-relay.dnsmasq.test,18h') in conf
