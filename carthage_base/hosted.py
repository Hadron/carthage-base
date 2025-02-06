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
import types
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
            file = model.state_path.joinpath(".host").open( "r+")
            close = True
            fcntl.lockf(file.fileno(), fcntl.LOCK_SH)
        res =  file.read()
        if not res: return None
        return res
    except FileNotFoundError: return None
    finally:
        if close: file.close()

def _sethost(model, host):
    fd = os.open(model.state_path/".host", os.O_CREAT|os.O_RDWR|os.O_CLOEXEC, 0o664)
    with open(fd, "r+t") as file:
        fcntl.lockf(fd,fcntl.LOCK_EX)
        cur_host = _checkhost(model, file=file)
        if cur_host and cur_host != host:
            raise RunningElsewhere(f'{model.name} is running on {cur_host}')
        os.truncate(fd,0)
        file.seek(0)
        file.write(host)

def clear_hosted(model):
    "Clear indication that a model's implementation is running somewhere.  The caller must guarantee the model is not running otherwise the model may be started in two locations."
    try: os.unlink(model.state_path/'.host')
    except FileNotFoundError: pass

__all__ += ['clear_hosted']

class RunningElsewhere(RuntimeError): pass

__all__ += ['RunningElsewhere']


            
@inject(host = InjectionKey("host"),
        model = InjectionKey(AbstractMachineModel, _optional=True, _ready=False),
        injector=Injector
        )
class HostedMachine(Injectable):

    remote_implementation = BareMetalMachine

    def __new__(cls, *, host, model, injector):
        config = injector.get_instance(ConfigLayout)
        if cls.is_locally_hosted(host,config, model):
            return cls.implementation
        return cls.remote_implementation

    @classmethod
    def is_locally_hosted(cls, host, config, model):
        if model and getattr(model, 'force_locally_hosted', False): return True
        if model:
            cur_host = _checkhost(model)
            if cur_host: return cur_host == socket.gethostname()
        if config.locally_hosted and  host in config.locally_hosted: return True
        if (not config.locally_hosted) or 'localhost' in config.locally_hosted:
            return host == socket.gethostname()
        return False

    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)
        if not issubclass(cls.implementation, HostedTrackerMixin):
            cls.implementation = types.new_class(
                cls.implementation.__qualname__,
                (cls.implementation, HostedTrackerMixin))

class HostedTrackerMixin(Machine):
    async def start_machine(self, **kwargs):
        _sethost(self.model, socket.gethostname())
        return await super().start_machine(**kwargs)

    async def stop_machine(self):
        clear_hosted(self.model)
        return await super().stop_machine()

__all__ += ['HostedTrackerMixin']

class HostedContainer(HostedMachine):
    implementation = carthage.container.Container

class HostedVm(HostedMachine):
    implementation = carthage.vm.Vm

@inject(host=None,
        model=InjectionKey(AbstractMachineModel, _ready=False))
class BareOrLocal(HostedMachine):
    implementation = carthage.local.LocalMachine

    def __new__(cls, *, injector, model, **kwargs):
        return super().__new__(cls, injector=injector, host=model.name, model=model, **kwargs)

__all__ += ['HostedContainer', 'HostedVm', 'BareOrLocal']
