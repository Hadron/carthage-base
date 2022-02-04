# Copyright (C) 2018, 2019, 2020, 2021, 2022, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

import fcntl
import os
import socket
from carthage import *
import carthage.container
import carthage.vm
import carthage.local
from carthage.machine import BareMetalMachine

__all__ = []

def _checkhost(model, file=None):
    try:
        close=False
        if not file:
            file = model.stamp_path.joinpath(".host").open( "r+")
            close = True
            fcntl.lockf(file.fileno(), fcntl.LOCK_SH)
        res =  file.read()
        if not res: return None
        return res
    except FileNotFoundError: return None
    finally:
        if close: file.close()

def _sethost(model, host):
    fd = os.open(model.stamp_path/".host", os.O_CREAT|os.O_RDWR, 0o664)
    with open(fd, "r+t") as file:
        fcntl.lockf(fd,fcntl.LOCK_EX)
        cur_host = _checkhost(model, file=file)
        if cur_host and cur_host != host:
            raise RunningElsewhere(f'{model.name} is running on {cur_host}')
        os.truncate(fd,0)
        file.seek(0)
        file.write(host)

class RunningElsewhere(RuntimeError): pass
__all__ += ['RunningElsewhere']

            
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
