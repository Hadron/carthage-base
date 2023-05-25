# Copyright (C) 2023, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

import pytest
from carthage import *
from carthage.modeling import *
from carthage.pytest import *
from carthage.podman import *
from carthage.oci import *
from layout import test_layout as layout
from carthage.plugins import load_plugin
base_injector(load_plugin, 'carthage.podman')

@async_test
async def test_bind9_role(ainjector):
    ainjector.add_provider(layout)
    l = await ainjector.get_instance_async(CarthageLayout)
    ainjector = l.ainjector
    try:
        await l.bind9_dns_server.async_become_ready()
        await l.bind9_dns_server.machine.async_become_ready()
        async with l.bind9_dns_server.machine.machine_running():
            zone = await ainjector.get_instance_async(InjectionKey(DnsZone, name='test.local'))
            await zone.update_records(
                ('foo.test.local', 'A', '1.2.3.4'))
    finally:
        try: await l.bind9_dns_server.machine.delete(force=True)
        except Exception: raise
    
