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
