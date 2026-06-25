# Copyright (C) 2026, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.

import pytest
import asyncio
from pathlib import Path
from carthage import *
from carthage.modeling import *
from carthage.podman import PodmanNetwork, PodmanContainer, PodmanImageModel
from carthage.oci import *
from carthage.pytest import async_test
from carthage_base import proxy
from carthage_base.proxy import ProxyConfig, build_proxy_service, ProxyServiceRole
from carthage.network import V4Config
from carthage.machine import BaseCustomization, FilesystemCustomization
from carthage.setup_tasks import setup_task

@pytest.fixture(scope='session')
def enable_podman():
    import carthage.plugins
    base_injector(carthage.plugins.load_plugin, 'carthage.podman')

class IntegrationProxyLayout(CarthageLayout):
    layout_name = 'integration_proxy'

    add_provider(machine_implementation_key, dependency_quote(PodmanContainer))

    @provides('proxy_net')
    class proxy_net(NetworkModel):
        v4_config = V4Config(
            network='172.16.0.0/24',
            pool=('172.16.0.10', '172.16.0.20'))
        instantiated = injector_access(PodmanNetwork)

    class BackendImage(PodmanImageModel):
        base_image = 'debian:trixie-slim'
        oci_image_tag = 'localhost/proxy-backend:latest'
        oci_image_command = ['sh', '-c', 'cd /app && python3 -m http.server 80']
        oci_interactive = True

        class install_python(FilesystemCustomization):
            runas_user = 'root'
            @setup_task("Install Python")
            async def install_python(self):
                await self.run_command('apt-get', 'update')
                await self.run_command('apt-get', 'install', '-y', 'python3')
                await self.run_command('mkdir', '-p', '/app')
                self.path.joinpath('app/index.html').write_text('Carthage Backend Success')
                # Ensure we are in the directory with the file when http.server starts
                # The oci_image_command needs to run from where the file is


    class BackendService(ProxyServiceRole, MachineModel):
        add_provider(oci_container_image, injector_access(BackendImage))
        add_provider(proxy.ProxyService(
            service='test-api',
            downstream='http://{public_name}/',
            upstream='http://{upstream_ip}/'
        ))
        
        name = 'backend'
        
        class net_config(NetworkConfigModel):
            add('eth0', net=InjectionKey('proxy_net'), mac=None)
    class ClientImage(PodmanImageModel):
        base_image = 'debian:trixie-slim'
        oci_image_tag = 'localhost/proxy-client:latest'
        oci_image_command = ['sleep', 'infinity']
        oci_interactive = True

    class ClientMachine(MachineModel):
        add_provider(oci_container_image, injector_access(ClientImage))
        name = 'client'
        
        class net_config(NetworkConfigModel):
            add('eth0', net=InjectionKey('proxy_net'), mac=None)

        class install_curl(FilesystemCustomization):
            runas_user = 'root'

            @setup_task("Install Curl")
            async def install_curl(self):
                await self.run_command('apt-get', 'update')
                await self.run_command('apt-get', 'install', '-y', 'curl')

@pytest.fixture(params=[
    pytest.param((proxy.ApacheProxyRole, proxy.ApacheProxyImage), id='apache'),
    pytest.param((proxy.NginxProxyRole, proxy.NginxProxyImage), id='nginx')
], autouse=False)
def proxy_layout(request, loop, ainjector, enable_podman):
    role, img_cls = request.param
    
    class TestLayout(IntegrationProxyLayout):
        class ProxyServerImage(img_cls):
            oci_interactive = True
        
        class ProxyServer(role, MachineModel):
            add_provider(oci_container_image, injector_access(ProxyServerImage))
            
            class net_config(NetworkConfigModel):
                add('eth0', net=InjectionKey('proxy_net'), mac=None)

    ainjector.add_provider(TestLayout)
    layout = loop.run_until_complete(ainjector.get_instance_async(TestLayout))
    yield layout
    
    async def cleanup():
        # Get the main machines from this layout context to delete them
        backend = await layout.ainjector.get_instance_async(IntegrationProxyLayout.BackendService)
        client = await layout.ainjector.get_instance_async(IntegrationProxyLayout.ClientMachine)
        proxy_server = await layout.ainjector.get_instance_async(InjectionKey(proxy.ProxyProtocol))
        await asyncio.gather(*[m.machine.delete() for m in [backend, client, proxy_server]])

    loop.run_until_complete(cleanup())

@async_test
async def test_proxy_integration(proxy_layout, ainjector):
    l = proxy_layout
    proxy_server = await l.ainjector.get_instance_async(InjectionKey(proxy.ProxyProtocol))
    backend = await l.ainjector.get_instance_async(IntegrationProxyLayout.BackendService)
    client = await l.ainjector.get_instance_async(IntegrationProxyLayout.ClientMachine)

    await asyncio.gather(
        backend.machine.async_become_ready(),
        proxy_server.machine.async_become_ready(),
        client.machine.async_become_ready(),
    )

    async with backend.machine.machine_running(), \
           proxy_server.machine.machine_running(), \
           client.machine.machine_running():
        
        # Disable default site by removing the symlink manually

        # Get the public name of the backend service to use as the Host header
        public_name = await backend.ainjector.get_instance_async(proxy.public_name_key)
        
        proxy_ip = str(proxy_server.machine.network_links['eth0'].merged_v4_config.address)
        cmd = f"curl -s -H 'Host: {public_name}' http://{proxy_ip}/"
        result = await client.machine.container_exec('sh', '-c', cmd)
        
        print(f"\n--- Curl Request ---")
        print(f"Backend Public Name: {public_name}")
        print(f"Command: {cmd}")
        print(f"Exit Code: {result.exit_code}")
        print(f"Stdout: {result.stdout}")
        print(f"Stderr: {result.stderr}")
        print(f"--------------------\n")

        assert result.exit_code == 0, f"Curl request failed with exit code {result.exit_code}: {result.stderr}"
        stdout_text = result.stdout.decode('utf-8', errors='ignore')
        assert "Carthage Backend Success" in stdout_text, f"Expected 'Carthage Backend Success' in response, but got: {stdout_text}"
        # Cleanup is handled by the fixture, but we can do local cleanup if needed
        pass

@async_test
async def test_proxy_config_contains_backend(proxy_layout, ainjector):
    l = proxy_layout
    proxy_server = await l.ainjector.get_instance_async(InjectionKey(proxy.ProxyProtocol))
    backend = await l.ainjector.get_instance_async(IntegrationProxyLayout.BackendService)

    # Get the config used by the proxy server
    proxy_server_config = await proxy_server.ainjector.get_instance_async(ProxyConfig)
    
    # Verify that the Backend Model is registered in this specific config
    print(f"\n--- Proxy Server Config: Proxied Models ---")
    proxied_names = [m.name for m in proxy_server_config.proxied_models]
    print(f"Proxied Models: {proxied_names}")
    print(f"----------------------------------\n")

    assert backend in proxy_server_config.proxied_models, \
        f"Backend service {backend.name} not found in the Proxy Server's config"

    # We must make backend ready to get its IP for the second check
    await backend.machine.async_become_ready()
    backend_ip = str(backend.machine.network_links['eth0'].merged_v4_config.address)
    print(f"\n--- Proxy Server Config: Services ---")
    services_list = []
    for s in proxy_server_config.services.values():
        services_list.append(s.upstream)
        print(f"Service: {s.service} | Upstream: {s.upstream}")
    print(f"----------------------------\n")

    found_service = any(backend_ip in up for up in services_list)
    assert found_service, \
        f"No proxy service found pointing to backend IP {backend_ip}. Found: {services_list}"
