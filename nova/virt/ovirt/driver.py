# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012-2013 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#
# Refer to the README and COPYING files for full details of the license

"""
A connection to the oVirt engine.

**Related Flags**

:ovirt_url:       URL of the oVirt engine
:ovirt_username:  Username for connection to the oVirt engine.
:ovirt_password:  Password for connection the oVirt engine.

"""

import time

from eventlet import event

from nova import exception
from nova.openstack.common import cfg
from nova.openstack.common import log as logging
from nova.compute import power_state
from nova import utils
from nova.virt import driver
from ovirtsdk.api import API
from ovirtsdk.xml import params

LOG = logging.getLogger(__name__)

ovirt_opts = [
    cfg.StrOpt('ovirt_url',
               default=None,
               help='URL for connection to oVirt engine host host.Required if '
                    'compute_driver is ovirt.OvirtDriver.'),
    cfg.StrOpt('ovirt_username',
               default=None,
               help='Username for connection to the oVirt engine. '
                    'Used only if compute_driver is '
                    'ovirt.OvirtDriver.'),
    cfg.StrOpt('ovirt_password',
               default=None,
               help='Password for connection to the oVirt engine. '
                    'Used only if compute_driver is '
                    'ovirt.OvirtDriver.'),
    ]

CONF = cfg.CONF
CONF.register_opts(ovirt_opts)

class OvirtDriver(driver.ComputeDriver):
    """The oVirt engine driver object."""

    def __init__(self):
        super(OvirtDriver, self).__init__()
        LOG.info(_("init in progress"))
        engine_url = CONF.ovirt_url
        engine_username = CONF.ovirt_username
        engine_password = CONF.ovirt_password
        if not engine_url or engine_username is None or engine_password is None:
            raise Exception(_("Must specify ovirt_url,"
                              "ovirt_username "
                              "and ovirt_password to use"
                              "compute_driver=ovirt.OvirtDriver"))

        self.session = API(url=engine_url, username=engine_username, password=engine_password)
        LOG.info(_("created session"))

    def init_host(self, host):
        """Initialize anything that is necessary for the driver to function,
        including catching up with currently running VM's on the given host."""
        pass

    def get_info(self, instance):
        """Get the current status of an instance, by name (not ID!)

        Returns a dict containing:

        :state:           the running state, one of the power_state codes
        :max_mem:         (int) the maximum memory in KBytes allowed
        :mem:             (int) the memory in KBytes used by the domain
        :num_cpu:         (int) the number of virtual CPUs for the domain
        :cpu_time:        (int) the CPU time used in nanoseconds
        """
        return dict(
            state=power_state.RUNNING,
            max_mem=1024,
            mem=1024,
            num_cpu=1,
            cpu_time=0,
        )

    def list_instances(self):
        """
        Return the names of all the instances known to the virtualization
        layer, as a list.
        """
        """List VM instances."""
        LOG.info(_("listing instances"))
        instances = self.session.vms.list()
        instance_names = []
        for instance in instances:
            instance_names.append(instance.name)
        return instance_names

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """
        Create a new instance/VM/domain on the virtualization platform.

        Once this successfully completes, the instance should be
        running (power_state.RUNNING).

        If this fails, any partial instance should be completely
        cleaned up, and the virtualization platform should be in the state
        that it was before this call began.

        :param context: security context
        :param instance: Instance object as returned by DB layer.
                         This function should use the data there to guide
                         the creation of the new instance.
        :param image_meta: image object returned by nova.image.glance that
                           defines the image from which to boot this instance
        :param injected_files: User files to inject into instance.
        :param admin_password: Administrator password to set in instance.
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices to be
                                  attached to the instance.
        """
        #open("/tmp/instance.debug", "a").write("[%s, %s, %s, %s, %s, %s, %s]" %
        #     (context.to_dict(), instance, image_meta, injected_files, admin_password,
        #      network_info, block_device_info))
        LOG.info(_("spawn"))
        vms_resource = self.session.vms
        vm_name = instance['name']
        create_vm_params = params.VM(name = vm_name, cluster = self.session.clusters.get(name='Default'), template = self.session.templates.get(name = image_meta['name']))
        new_vm = vms_resource.add(create_vm_params)
        LOG.info(_(new_vm.status.state))
        while (new_vm.status.state == 'image_locked'):
            new_vm = vms_resource.get(name = vm_name)
        if (new_vm.status.state == 'down'):
            new_vm.start()

    def _stop(self, vm_name):
        LOG.info(_("_stop"))
        vms_resource = self.session.vms
        vm = vms_resource.get(name = vm_name)
        if (vm.status.state != 'down'):
            vm.stop()
        vm = vms_resource.get(name = vm_name)
        while (vm.status.state != 'down'):
            vm = vms_resource.get(name = vm_name)

    def destroy(self, instance, network_info, block_device_info=None):
        """Destroy (shutdown and delete) the specified instance.

        If the instance is not found (for example if networking failed), this
        function should still succeed.  It's probably a good idea to log a
        warning in that case.

        :param instance: Instance object as returned by DB layer.
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices that should
                                  be detached from the instance.

        """
        LOG.info(_("delete"))
        vm_name = instance['name']
        self._stop(vm_name)
        vm = self.session.vms.get(name = vm_name)
        vm.delete()

    def reboot(self, instance, network_info, reboot_type,
               block_device_info=None):
        """Reboot the specified instance.

        :param instance: Instance object as returned by DB layer.
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param reboot_type: Either a HARD or SOFT reboot
        """
        vm_name = instance['name']
        self._stop(vm_name)
        self.session.vms.get(name = vm_name).start()

    def get_console_pool_info(self, console_type):
        raise NotImplementedError()

    def get_console_output(self, instance):
        raise NotImplementedError()

    def get_vnc_console(self, instance):
        raise NotImplementedError()

    def get_diagnostics(self, instance):
        """Return data about VM diagnostics"""
        return dict(metric1='value1')

    def get_host_ip_addr(self):
        """
        Retrieves the IP address of the dom0
        """
        return '1.1.1.1'

    def attach_volume(self, connection_info, instance_name, mountpoint):
        """Attach the disk to the instance at mountpoint using info"""
        for key,value in connection_info.items():
            print key,value
# vm = self.session.vms.get(name = instnace_name)
# disk_id = connection_info.my_disk_id ????
# vm.disks.add(params.Disk(id="e4c66094-2296-4b8a-95c5-394da7b82729",active=True))
        vm = self.session.vms.get(name = instance_name)
        disk_id = connection_info['uuid']
        vm.disks.add(params.Disk(id = disk_id,active = True))

    def detach_volume(self, connection_info, instance_name, mountpoint):
        """Detach the disk attached to the instance"""
        raise NotImplementedError()

    def snapshot(self, context, instance, image_id):
        """
        Snapshots the specified instance.

        :param context: security context
        :param instance: Instance object as returned by DB layer.
        :param image_id: Reference to a pre-created image that will
                         hold the snapshot.
        """
        LOG.info(_("snapshot"))
        vm_name = instance['name']
        vm_to_snapshot = self.session.vms.get(name = vm_name)
        vm_to_snapshot.snapshots.add(params.Snapshot(description = 'snapshot', vm = vm_to_snapshot))
        while self.session.vms.get(name = vm_name).status.state == 'image_locked':
            sleep(1)
        LOG.info(_("finished creating snapshot"))

    def pause(self, instance):
        """Pause the specified instance."""
        LOG.info(_("pause"))
        self.session.vms.get(name = instance['name']).suspend()

    def unpause(self, instance):
        """Unpause paused VM instance"""
        LOG.info(_("unpause"))

        self.session.vms.get(name = instance['name']).start()

    def suspend(self, instance):
        """suspend the specified instance"""
        LOG.info(_("suspend"))
        self.session.vms.get(name = instance['name']).suspend()

    def resume(self, instance):
        """resume the specified instance"""
        LOG.info(_("resume"))
        self.session.vms.get(name = instance['name']).start()

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        """resume guest state when a host is booted"""
        raise NotImplementedError()

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        """Rescue the specified instance"""
        raise NotImplementedError()

    def unrescue(self, instance, network_info):
        """Unrescue the specified instance"""
        raise NotImplementedError()

    def power_off(self, instance):
        """Power off the specified instance."""
        raise NotImplementedError()

    def power_on(self, instance):
        """Power on the specified instance"""
        raise NotImplementedError()

    def get_available_resource(self):
        """Retrieve resource information.

        This method is called when nova-compute launches, and
        as part of a periodic task

        :returns: Dictionary describing resources
        """
        return dict(
            vcpus=100,
            memory_mb=25600,
            local_gb=10000,
            cpu_info='alon',
            vcpus_used=0,
            memory_mb_used=0,
            local_gb_used=0,
        )

    def refresh_security_group_rules(self, security_group_id):
        """This method is called after a change to security groups.

        All security groups and their associated rules live in the datastore,
        and calling this method should apply the updated rules to instances
        running the specified security group.

        An error should be raised if the operation cannot complete.

        """
        pass

    def refresh_security_group_members(self, security_group_id):
        """This method is called when a security group is added to an instance.

        This message is sent to the virtualization drivers on hosts that are
        running an instance that belongs to a security group that has a rule
        that references the security group identified by `security_group_id`.
        It is the responsibility of this method to make sure any rules
        that authorize traffic flow with members of the security group are
        updated and any new members can communicate, and any removed members
        cannot.

        Scenario:
            * we are running on host 'H0' and we have an instance 'i-0'.
            * instance 'i-0' is a member of security group 'speaks-b'
            * group 'speaks-b' has an ingress rule that authorizes group 'b'
            * another host 'H1' runs an instance 'i-1'
            * instance 'i-1' is a member of security group 'b'

            When 'i-1' launches or terminates we will receive the message
            to update members of group 'b', at which time we will make
            any changes needed to the rules for instance 'i-0' to allow
            or deny traffic coming from 'i-1', depending on if it is being
            added or removed from the group.

        In this scenario, 'i-1' could just as easily have been running on our
        host 'H0' and this method would still have been called.  The point was
        that this method isn't called on the host where instances of that
        group are running (as is the case with
        :py:meth:`refresh_security_group_rules`) but is called where references
        are made to authorizing those instances.

        An error should be raised if the operation cannot complete.

        """
        pass

    def refresh_provider_fw_rules(self):
        """This triggers a firewall update based on database changes.

        When this is called, rules have either been added or removed from the
        datastore.  You can retrieve rules with
        :py:meth:`nova.db.provider_fw_rule_get_all`.

        Provider rules take precedence over security group rules.  If an IP
        would be allowed by a security group ingress rule, but blocked by
        a provider rule, then packets from the IP are dropped.  This includes
        intra-project traffic in the case of the allow_project_net_traffic
        flag for the libvirt-derived classes.

        """
        pass

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        """Setting up filtering rules and waiting for its completion.

        To migrate an instance, filtering rules to hypervisors
        and firewalls are inevitable on destination host.
        ( Waiting only for filtering rules to hypervisor,
        since filtering rules to firewall rules can be set faster).

        Concretely, the below method must be called.
        - setup_basic_filtering (for nova-basic, etc.)
        - prepare_instance_filter(for nova-instance-instance-xxx, etc.)

        to_xml may have to be called since it defines PROJNET, PROJMASK.
        but libvirt migrates those value through migrateToURI(),
        so , no need to be called.

        Don't use thread for this method since migration should
        not be started when setting-up filtering rules operations
        are not completed.

        :params instance_ref: nova.db.sqlalchemy.models.Instance object

        """
        pass

    def unfilter_instance(self, instance, network_info):
        """Stop filtering instance"""
        pass

    def poll_rebooting_instances(self, timeout):
        """Poll for rebooting instances"""
        raise NotImplementedError()

    def poll_rescued_instances(self, timeout):
        """Poll for rescued instances"""
        raise NotImplementedError()

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        raise NotImplementedError()

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation."""
        raise NotImplementedError()

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        raise NotImplementedError()

    def get_host_uptime(self, host):
        """Returns the result of calling "uptime" on the target host."""
        raise NotImplementedError()

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        pass

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        pass

    def update_host_status(self):
        """Refresh host stats"""
        pass

    def get_host_stats(self, refresh=False):
        """Return currently known host stats"""
        return dict(
            vcpus=1,
            vcpus_used=1,
            cpu_info='alon2',
            disk_total=50,
            disk_used=10,
            disk_available=40,
            host_memory_total=2560,
            host_memory_free=200,
            hypervisor_type='oVirt',
            hypervisor_version='0',
            hypervisor_hostname='openstack-ovirt-dev1.eng.lab.tlv.redhat.com',
            supported_instances=[dict(arch='x86_64', hypervisor_type='oVirt', vm_mod='test1')],
        )

    def block_stats(self, instance_name, disk_id):
        """
        Return performance counters associated with the given disk_id on the
        given instance_name.  These are returned as [rd_req, rd_bytes, wr_req,
        wr_bytes, errs], where rd indicates read, wr indicates write, req is
        the total number of I/O requests made, bytes is the total number of
        bytes transferred, and errs is the number of requests held up due to a
        full pipeline.

        All counters are long integers.

        This method is optional.  On some platforms (e.g. XenAPI) performance
        statistics can be retrieved directly in aggregate form, without Nova
        having to do the aggregation.  On those platforms, this method is
        unused.

        Note that this function takes an instance ID.
        """
        raise NotImplementedError()

    def interface_stats(self, instance_name, iface_id):
        """
        Return performance counters associated with the given iface_id on the
        given instance_id.  These are returned as [rx_bytes, rx_packets,
        rx_errs, rx_drop, tx_bytes, tx_packets, tx_errs, tx_drop], where rx
        indicates receive, tx indicates transmit, bytes and packets indicate
        the total number of bytes or packets transferred, and errs and dropped
        is the total number of packets failed / dropped.

        All counters are long integers.

        This method is optional.  On some platforms (e.g. XenAPI) performance
        statistics can be retrieved directly in aggregate form, without Nova
        having to do the aggregation.  On those platforms, this method is
        unused.

        Note that this function takes an instance ID.
        """
        raise NotImplementedError()

    def legacy_nwinfo(self):
        """
        Indicate if the driver requires the legacy network_info format.
        """
        return False

    def manage_image_cache(self, context):
        """
        Manage the driver's local image cache.

        Some drivers chose to cache images for instances on disk. This method
        is an opportunity to do management of that cache which isn't directly
        related to other calls into the driver. The prime example is to clean
        the cache and remove images which are no longer of interest.
        """
        pass

    def get_volume_connector(self, _instance):
        """Return volume connector information"""
        # TODO(vish): When volume attaching is supported, return the
        #             proper initiator iqn and host.
        return {
            'ip': None,
            'initiator': None,
            'host': None
        }

