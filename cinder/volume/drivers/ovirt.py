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
Driver for ovirt volumes.

"""

import logging
import ovirtsdk.api
from ovirtsdk.xml.params import Disk, StorageDomains

from cinder import flags
from cinder.openstack.common import cfg

LOG = logging.getLogger(__name__)

volume_opts = [
    cfg.StrOpt('ovirt_engine_url',
               default='http://localhost:8700/api',
               help=''),
    cfg.StrOpt('ovirt_engine_username',
               default='admin@internal',
               help=''),
    cfg.StrOpt('ovirt_engine_password',
               default='letmein!',
               help=''),
    cfg.StrOpt('ovirt_engine_storagedomain',
               default='OpenStackDomain',
               help=''),
    cfg.StrOpt('ovirt_engine_sparse',
               default=True,
               help=''),
]

FLAGS = flags.FLAGS
FLAGS.register_opts(volume_opts)


class OVirtDriver(object):
    VOLSIZE_MULT = 2 ** 30  # Gigabytes to bytes

    def do_setup(self, context):
        """Any initialization the volume driver does while starting"""
        self._engine = ovirtsdk.api.API(FLAGS.ovirt_engine_url,
                    FLAGS.ovirt_engine_username, FLAGS.ovirt_engine_password)

    def check_for_setup_error(self):
        """No setup necessary in fake mode."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreates an export for a logical volume."""
        # raise NotImplementedError()

    def create_export(self, context, volume):
        """Exports the volume. Can optionally return a Dictionary of changes
        to the volume object to be persisted."""
        # raise NotImplementedError()

    def remove_export(self, context, volume):
        """Removes an export for a logical volume."""
        # raise NotImplementedError()

    def initialize_connection(self, volume, connector):
        """Allow connection to connector and return connection info."""
        raise NotImplementedError()

    def terminate_connection(self, volume, connector, force=False, **kwargs):
        """Disallow connection from connector"""
        raise NotImplementedError()

    def _get_volume_name(self, name):
        return "openstack-" + name

    def create_volume(self, volume):
        os_domain = self._engine.storagedomains.get(
                                            FLAGS.ovirt_engine_storagedomain)
        request = Disk(
            name=self._get_volume_name(volume['name']),
            storage_domains=StorageDomains(storage_domain=[os_domain]),
            size=(volume['size'] * self.VOLSIZE_MULT), type_='data',
            interface='virtio', format='raw', sparse=FLAGS.ovirt_engine_sparse)
        response = self._engine.disks.add(request)

    def get_volume_stats(self, refresh=False):
        """Return the current state of the volume service. If 'refresh' is
           True, run the update first."""
        return None

    def delete_volume(self, volume):
        for disk in self._engine.disks.list(
                        name=self._get_volume_name(volume['name'])):
            disk.delete()
        return True
