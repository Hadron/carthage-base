# Copyright (C) 2018, 2019, 2020, 2021, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
import socket
from carthage import *
import carthage.container
import carthage.vm
import carthage.local
from carthage.machine import BareMetalMachine

__all__ = []

@inject(host = InjectionKey("host"),
        injector=Injector
        )
class HostedMachine(Injectable):

    def __new__(cls, *, host, injector):
        config = injector.get_instance(ConfigLayout)
        if cls.is_locally_hosted(host,config):
            return cls.implementation
        return BareMetalMachine

    @classmethod
    def is_locally_hosted(cls, host, config):
        if config.locally_hosted: return host in config.locally_hosted
        return host == socket.getfqdn()

class HostedContainer(HostedMachine):
    implementation = carthage.container.Container

class HostedVm(HostedMachine):
    implementation = carthage.vm.Vm

@inject(host=None,
        model=AbstractMachineModel)
class BareOrLocal(HostedMachine):
    implementation = carthage.local.LocalMachine

    def __new__(cls, *, injector, model, **kwargs):
        return super().__new__(cls, injector=injector, host=model.name, **kwargs)

__all__ += ['HostedContainer', 'HostedVm', 'BareOrLocal']
