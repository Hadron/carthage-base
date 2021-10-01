# Copyright (C) 2021, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

from carthage.config import ConfigSchema

class CarthageBaseSchema(ConfigSchema, prefix=""):

    #: List of hosts that we host the VMs for.  If empty, then gethostname() is used, otherwise any VM/Container hosted on one of the listed machines is handled locally.
    locally_hosted: list
    
