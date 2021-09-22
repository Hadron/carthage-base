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

__all__ = []

@inject(host = InjectionKey("host"),
        )
class HostedMachine(Injectable):

    def __new__(cls, *, host):
        if cls.is_locally_hosted(host):
            return cls.implementation
        return BareMetalMachine

    @classmethod
    def is_locally_hosted(cls, host):
        return host == socket.getfqdn()

class HostedContainer(HostedMachine):
    implementation = carthage.container.Container

class HostedVm(HostedMachine):
    implementation = carthage.vm.Vm

__all__ += ['HostedContainer', 'HostedVm']
