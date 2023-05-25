# Copyright (C) 2018, 2019, 2020, 2021, 2022, Hadron Industries, Inc.
# Carthage is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation. It is distributed
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for details.
import os.path
from pathlib import Path
import types
import carthage
import carthage.systemd
from carthage import *
from carthage.modeling import *
from carthage.ssh import SshKey
from carthage.ansible import *
from carthage.sonic import SonicNetworkModelMixin
from carthage.oci import OciMount
from .pki import CertificateInstallationTask

__all__ = []

class DhcpRole(MachineModel, template = True):

    override_dependencies = True

    dnsmasq_conf = mako_task("dhcp-dnsmasq.conf",
                             output = "etc/dnsmasq.d/dhcp.conf",
                             model = InjectionKey(MachineModel))

    class dhcp_customization(MachineCustomization):

        @setup_task("install software")
        async def install_software(self):
            await self.ssh("apt -y install dnsmasq",
                           _bg = True,
                           _bg_exc = False)
            await self.ssh("systemctl disable --now systemd-resolved", _bg = True, _bg_exc = False)
            async with self.filesystem_access() as path:
                try: Path(path).joinpath("etc/resolv.conf").unlink()
                except FileNotFoundError: pass
                with                                     Path(path).joinpath("etc/resolv.conf").open("wt") as f:
                    f.write("nameserver 127.0.0.1\n")



        install_mako = install_mako_task('model')

        @setup_task("restart dnsmasq")
        async def restart_dnsmasq(self):
            if not self.running: return
            await self.ssh("systemctl restart dnsmasq",
                           _bg = True,
                           _bg_exc = False)

__all__ += ['DhcpRole']

class CarthageServerRole(ImageRole):

    project_destination = "/"

    #: If true (the default), then checkout_dir is synchronized to the destination
    copy_in_checkouts = True

    #:if True (the default), keep track of the git hashes of copied trees and copy again on change.
    carthage_role_track_git_changes = True

    class customize_for_carthage(FilesystemCustomization):

        libvirt_server_role = ansible_role_task('libvirt-server')

        @setup_task("Copy in carthage and layout")
        @inject(ainjector=AsyncInjector,
                config=ConfigLayout)
        async def copy_in_carthage(self, ainjector, config):
            host = self.host
            if isinstance(host, LocalMachine): raise SkipSetupTask
            project_destination = Path(host.model.project_destination)
            await self.run_command("mkdir", "-p", str(project_destination))
            await self.run_command('apt', 'update')
            await self.run_command("apt", *'-y install rsync sshfs'.split())
            await self.run_command("mkdir", "-p", config.checkout_dir)
            await ainjector(
                rsync_git_tree,
                os.path.dirname(carthage.__file__),
                RsyncPath(host, project_destination/"carthage"))
            if hasattr(host.model, 'layout_source'):
                await ainjector(
                    rsync_git_tree,
                    host.model.layout_source,
                    RsyncPath(host, project_destination/host.model.layout_destination))
            if host.model.copy_in_checkouts and Path(config.checkout_dir).exists():
                checkout_dir = config.checkout_dir
                await ainjector(
                    carthage.ssh.rsync,
                    "-a",
                    "--delete",
                    '--safe-links',
                    f'{checkout_dir}/',
                    RsyncPath(host, checkout_dir))

        @copy_in_carthage.hash()
        def copy_in_carthage(self):
            if not self.model.carthage_role_track_git_changes: return ""
            hashes = []
            hashes.append(git_tree_hash(os.path.dirname(carthage.__file__)))
            try:
                hashes.append(git_tree_hash(self.model.layout_source))
            except AttributeError: pass
            return str(hashes)


__all__ += ['CarthageServerRole']

@inject(authorized_keys=carthage.ssh.AuthorizedKeysFile)
class SonicMachineMixin(Machine, SetupTaskMixin):


    # We cannot just use a CustomizationTask in the model because we
    # need to force this role to be very early

    sonic_role = ansible_role_task(
        "sonic_config",
        before=carthage.systemd.SystemdNetworkInstallMixin.generate_config_dependency)

class SonicRole(SonicNetworkModelMixin, MachineModel, template=True):

    add_provider(InjectionKey(MachineMixin, name="sonic"), dependency_quote(SonicMachineMixin))

__all__ += ['SonicRole']

class StrongswanGatewayRole(MachineModel, template=True):

    #: If true, maintain trap policies for ipsec SAs; if 'start, actually start the SA on boot
    ipsec_maintain_sas = True
    connections_mako = mako_task(
        'strongswan-connections.mako',
        output='etc/swanctl/conf.d/carthage.conf',
        peers=InjectionKey("strongswan/peers"))

    @provides(InjectionKey("strongswan/peers"))
    @inject(self=AbstractMachineModel)
    async def strongswan_peers(self):
        def remote_addr(m):
            if hasattr(m, 'ipsec_address'): return m.ipsec_address
            try: return m.ip_address
            except (NotImplementedError, AttributeError): return None
        results = []
        for k, model in await self.ainjector.filter_instantiate_async(
                StrongswanGatewayRole, ['host'],
                ready=False):
            if model is self: continue
            results.append(types.SimpleNamespace(
                identity=model.name,
                remote_addr=remote_addr(model),
                remote_ts=model.child_ts,
                ))
        return results

    def __init_subclass__(cls, template=False, **kwargs):
        super().__init_subclass__(template=template, **kwargs)
        if not template:
            globally_unique_key(InjectionKey(StrongswanGatewayRole, host=cls.name))(cls)

    #: The xfrm interface id or None for inbound traffic
    if_id_in = None

    #: The xfrm interface ID or None for outbound traffic
    if_id_out = None

    #: Child traffic selectors
    child_ts = '0.0.0.0/0'

    class ipsec_customization(FilesystemCustomization):

        install_mako = install_mako_task('model')
        install_cert = CertificateInstallationTask(
            ca_path='/etc/swanctl/x509ca/carthage-ca.pem',
            cert_dir='/etc/swanctl/x509',
            key_dir='/etc/swanctl/rsa',
            stem='strongswan.pem',
            )


        install_strongswan = ansible_role_task('install-strongswan')

__all__ += ['StrongswanGatewayRole']

class Bind9Role(MachineModel, template=True):

    '''
    The *zones* property is a mapping of zone name to  of dicts containing the following:

    name
        The name of the zone

    type
        primary|secondary

    masters
        For a secondary zone, where to find the primary

    also_notify
        Additional addresses to notify (expressed as a list)

    allow_transfer
        Addresses to accept transfers from

    file
        Name of file in which zone data is stored

    update_keys
        Name of keys that can dynamically update the zone

    dnssec_policy
        Set the dnssec policy for the zone

    initial_records
        Initial records besides the SOA if the zone file does not exist.  Currently just a string dumped into the zone file.

    Also, the *named_options* mapping contains global options:

    allow_recursion
        A list of addresses to allow recursion from.


'''

    @memoproperty
    def zones_ns(self):
        result = {}
        if not hasattr(self, 'zones'): return result
        for name, zone in self.zones.items():
            for k in self.zone_options:
                if k == 'masters' and zone['type'] == 'primary':
                    continue
                if k not in zone: zone[k] = self.zone_options[k]
            result[name] = types.SimpleNamespace(**zone)
        return result

    @memoproperty
    def tsig_keys(self):
        results = set()
        for z in self.zones_ns.values():
            for k in getattr(z, 'update_keys', []):
                results.add(k)
        return results

    #: Directory for primary_zone data
    primary_zone_dir = "/etc/bind/zones"

    #: A set of options to merge into every zone definition.  Options in the zone override.  Masters is always removed from primary zones.
    zone_options = {}
    named_conf_local = mako_task('named.conf.local.mako',
                                 output='etc/bind/named.conf.local')
    named_conf_options = mako_task('named.conf.options.mako', output='etc/bind/named.conf.options')


    #: Global bind options
    named_options = {}
    def key_path(self, key):
        return self.stamp_path/f'tsig_keys/{key}.key'

    def __init_subclass__(cls, **kwargs):
        from .dns import Bind9DnsZone
        super().__init_subclass__(**kwargs)

        try: cls.zones
        except AttributeError: return
        for name, z in cls.zones.items():
            if 'update_keys' in z:
                cls.add_provider(
                                   InjectionKey(DnsZone, name=name, _globally_unique=True),
                                   when_needed(Bind9DnsZone, name=name),
                                   propagate=True)

    class dns_customization(FilesystemCustomization):

        description = "Customize for dns server"

        install_bind9 = ansible_role_task('install-bind9')

        install_mako = install_mako_task('model')

        @setup_task("Create any needed zones")
        async def create_zones(self):
            zone_stem = Path(self.model.primary_zone_dir).relative_to('/')
            zone_path = self.path/zone_stem
            if not zone_path.exists():
                zone_path.mkdir()
                await self.run_command(
                    'chown', 'bind', str(zone_stem))
                
            for z, options in self.model.zones_ns.items():
                if options.type != 'primary': continue
                this_zone_path = zone_path/options.file
                if not this_zone_path.exists():
                    initial_records = getattr(options, 'initial_records', None)
                    if initial_records is None:
                        initial_records = f'@ IN NS {self.model.name}.'
                        if z in self.model.name:
                            logger.warning(f'{z} zone is likely to fail because we need an address for {self.model.name} in the zone nameservers')
                    this_zone_path.write_text(f'''
{z}.		IN SOA	{self.model.name}. hostmaster.{self.model.name}. (
                                1 ; serial
                                36000      ; refresh (10 hours)
                                86400      ; retry (1 day)
                                2419200    ; expire (4 weeks)
                                4000       ; minimum (1 hour 6 minutes 40 seconds)
                                )
{initial_records}
''')
                    await self.run_command(
                        'chown', 'bind',
                        '/'+str(this_zone_path.relative_to(self.path)))


        @create_zones.hash()
        def create_zones(self):
            return str(list(self.model.zones_ns.keys()))

        @setup_task('Generate needed tsig keys')
        async def generate_tsig_keys(self, invalidate=False):
            key_path = self.path/"etc/bind"
            for k in self.model.tsig_keys:
                assert carthage.utils.validate_shell_safe(k)
                this_key_path = key_path/f'{k}.key'
                if invalidate or not this_key_path.exists():
                    await self.run_command(
                        'sh', '-c',
                        f'tsig-keygen {k} >/etc/bind/{k}.key'
                        )
                    await self.run_command(
                        'chown', 'bind',
                        f'/etc/bind/{k}.key')
                    await self.run_command(
                        'chmod', '600',
                        f'/etc/bind/{k}.key')

        @generate_tsig_keys.check_completed()
        async def generate_tsig_keys(self):
            # We do not return last_run because rerunning the task is not guaranteed to change stat times on the files
            async with self.host.filesystem_access() as path:
                key_path = path/"etc/bind"
                for k in self.model.tsig_keys:
                    if not key_path.joinpath(f'{k}.key').exists():
                        return False
            return True

        @setup_task("Gather tsig keys for model")
        async def gather_tsig_keys(self):
            key_dir = self.path/"etc/bind"
            model_key_dir = self.model.stamp_path/"tsig_keys"
            model_key_dir.mkdir(mode=0o700, exist_ok=True)
            for k in self.model.tsig_keys:
                key_stem = f'{k}.key'
                model_key = model_key_dir/key_stem
                key_path = key_dir/key_stem
                model_key.touch(mode=0o600)
                model_key.write_text(key_path.read_text())

        @gather_tsig_keys.check_completed()
        async def gather_tsig_keys(self):
            last = 0.0
            async with self.host.filesystem_access() as path:
                key_path = path/"etc/bind"
                model_key_path = self.model.stamp_path/"tsig_keys"
                if not model_key_path.exists(): return False
                for k in self.model.tsig_keys:
                    key_stem = f'{k}.key'
                    try: model_stat = model_key_path.joinpath(key_stem).stat()
                    except FileNotFoundError: return False
                    stat = key_path.joinpath(key_stem).stat()
                    if stat.st_mtime > model_stat.st_mtime:
                        return False
                    if model_stat.st_mtime > last:
                        last = model_stat.st_mtime
            return last


        @setup_task('reload bind')
        async def reload_bind(self):
            try: await self.run_command('/bin/systemctl', 'start', 'bind9')
            except Exception: pass
            await self.run_command('rndc', 'reconfig')
            await self.run_command('rndc', 'reload')

__all__ += ['Bind9Role']

class PostgresRole(MachineModel, template=True):

    pg_user = 'database' #: user to create
    pg_database = 'database' #: Name of Database to create
    pg_password = 'password' #: Password for pg_user

    #: if not None, register OCIMounts for /var/lib/postgresql and /etc/postgresql; if run in a container these will be volume mounts.
    pg_volume_stem = None

    # In case we are run in a OCI container
    oci_command = ['/bin/systemd']

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.pg_volume_stem:
            self.injector.add_provider(
                OciMount('/var/lib/postgresql', self.pg_volume_stem))
            self.injector.add_provider(
                OciMount('/etc/postgresql', self.pg_volume_stem+'_etc'))

    class postgres_actions(FilesystemCustomization):

        @setup_task("Install Postgres")
        async def install_postgres(self):
            await self.run_command(
                'apt', '-y', 'install',
                'postgresql')

        @setup_task("Set up database and user")
        async def setup_database(self):
            pg_password = self.model.pg_password.replace("'", "''")
            self.path.joinpath('create.sql').write_text(
                f'''
                create user {self.model.pg_user} password '{pg_password}';
                create database {self.model.pg_database} owner {self.model.pg_user};
                ''')
            await self.run_command('/bin/systemctl', 'start', 'postgresql')
            await self.run_command(
                'runuser', 'postgres',
                'sh', '-c',
                'psql template1 </create.sql')

__all__ += ['PostgresRole']
