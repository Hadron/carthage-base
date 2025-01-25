# Copyright (C) 2022, 2024, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
import collections.abc
from ipaddress import IPv4Address
from carthage import sh
from carthage.dependency_injection import *
from carthage.modeling import *
from carthage import AbstractMachineModel, DnsZone


@inject_autokwargs(
    model = AbstractMachineModel
    )
class Bind9DnsZone(InjectableModel, DnsZone):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        zone_info = self.model.zones_ns.get(self.name)
        if zone_info is None:
            raise ValueError(f'{self.model} does not define {self.name} as a DNS zone')
        if not getattr(zone_info, 'update_keys', None):
            raise ValueError('Instantiating a zone without update_keys does not make sense')
        self.zone_info = zone_info

    @property
    def key_path(self):
        '''
        returns the Path to an update key for this zone.
        '''
        return self.model.key_path(self.zone_info.update_keys[0])


    async def update_records(self, *args, ttl=300):
        await self.async_become_ready()
        await self.model.machine.async_become_ready()
        if not self.model.machine.running: await self.model.machine.start_machine()
        update = f"zone {self.name}\n"
        try:
            server = self.zone_info.update_server
            server = await resolve_deferred(self.ainjector, server, args=dict(zone=self.name))
            update += f'server {server}\n'
        except AttributeError: pass
        for a in args:
            assert isinstance(a, collections.abc.Sequence), "Each update must be a Sequence"
            name, rrtype, values = a
            if ( not isinstance(values, collections.abc.Sequence)) or isinstance(values, str):
                values = (values,)
            if not self.contains(name):
                raise ValueError(f'{name} not in {self.name} zone')
            if not name.endswith('.'): name += '.'
            update += f"del {name} IN {rrtype}\n"
            for v in values:
                update += f"add {name} {ttl} IN {rrtype} {v}\n"
        update += "send\n"

        await sh.nsupdate('-k', self.key_path,
                          _in=update,
                          _bg=True, _bg_exc=False)
        
@inject(model=AbstractMachineModel)
async def default_ns_for_zone(*, model, zone):
    '''
    Generates an NS record claiming that the model itself is the
    nameserver for the zone.  If the model's name is within the zone,
    then look up the model's IP address and insert an A record.
    '''
    result = f'''\
@               IN      NS      {model.name}.
'''
    if model.name.endswith(zone):
        if not model.machine.running: await model.machine.start_machine()
        assert IPv4Address(model.machine.ip_address), "Don't know how to get IP address for zone"
        result += f'''\
{model.name}. IN        A       {model.machine.ip_address}
'''
    return result
