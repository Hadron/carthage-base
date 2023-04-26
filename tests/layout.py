# Copyright (C) 2023, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

import os
from pathlib import Path
from carthage import *
from carthage.cloud_init import WriteAuthorizedKeysPlugin
from carthage.modeling import *
from carthage_aws import *
from carthage_base import *
from carthage_base.proxy import *
from carthage.podman import *
from carthage.oci import *

class test_layout(CarthageLayout, PublicDnsManagement):


    add_provider(InjectionKey(DnsZone, role='public_zone'),
                 when_needed(AwsHostedZone, name="autotest.photon.ac",
                             addl_keys=[InjectionKey(DnsZone, domain='autotest.photon.ac')]))
    add_provider(WriteAuthorizedKeysPlugin, allow_multiple=True)
    add_provider(InjectionKey('aws_ami'), image_provider(owner=debian_ami_owner, name='debian-11-amd64-*'))

    add_provider(oci_container_image, 'debian:latest')
    oci_interactive = True
    
    add_provider(machine_implementation_key, dependency_quote(PodmanContainer))
    add_provider(ProxyConfig)

    domain = 'autotest.photon.ac'
    
    @provides("proxy_image")
    class proxy_image(ProxyImageRole, PodmanImageModel):
        oci_image_tag = 'proxy:latest'

    class aws_net(NetworkModel):
                v4_config = V4Config(network="192.168.100.0/24")
                aws_security_groups = ['all_open']

    class test_runner(CarthageServerRole, AnsibleModelMixin, MachineModel):

        add_provider(machine_implementation_key, MaybeLocalAwsVm)
        cloud_init = True

        aws_instance_type = 't3.medium'
        name = 'test-runner'
        layout_source = os.path.dirname(__file__)
        layout_destination = "carthage_base"
        aws_iam_profile = "ec2_full"
        config_info = mako_task("config.yml.mako", output="carthage_base/config.yml", config=InjectionKey(ConfigLayout))

        class install(MachineCustomization):

            @setup_task("install software")
            async def install_software(self):
                await self.ssh("apt -y install python3-pip rsync python3-pytest ansible",
                               _bg=True, _bg_exc=False)
                await self.ssh("pip3 install boto3", _bg=True, _bg_exc=False)
                await self.ssh('systemctl enable --now systemd-resolved', _bg=True, _bg_exc=False)

            install_mako = install_mako_task('model')

        class net_config(NetworkConfigModel):
            add('eth0', mac=None, net=InjectionKey('aws_net'))
            

    class webserver(ProxyServerRole, PkiCertRole):
        add_provider(OciExposedPort(80, host_port=8801))
        add_provider(OciExposedPort(443, host_port=8802))
        add_provider(oci_container_image, injector_access(proxy_image))
        

    class microservice(ProxyServiceRole):
        add_provider(OciExposedPort(container_port=80, host_port=8880))
