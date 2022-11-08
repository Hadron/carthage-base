# Copyright (C) 2022, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
import collections.abc
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


    async def update_records(self, *args, ttl=300):
        await self.async_become_ready()
        await self.model.machine.async_become_ready()
        if not self.model.machine.running: await self.model.machine.start_machine()
        key_path = self.model.key_path(self.zone_info.update_keys[0])
        update = f"zone {self.name}\n"
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
        print(update)
        await sh.nsupdate('-k', key_path,
                          _in=update,
                          _bg=True, _bg_exc=False)
        
