# Copyright 2016 Mirantis Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Module for storing ZFSonLinux driver utility stuff such as:
- Common ZFS code
- Share helpers
"""

import abc

from oslo_log import log
import six

from manila.common import constants
from manila import exception
from manila.i18n import _, _LW
from manila.share import driver
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila.share.drivers.zfsonlinux import constants as zfs_constants
from manila import utils

LOG = log.getLogger(__name__)


class ExecuteMixin(driver.ExecuteMixin):

    def init_execute_mixin(self, *args, **kwargs):
        """Init method for mixin called in the end of driver's __init__()."""
        super(ExecuteMixin, self).init_execute_mixin(*args, **kwargs)
        if self.configuration.zfs_use_ssh:
            self.ssh_executor = ganesha_utils.SSHExecutor(
                ip=self.configuration.zfs_share_export_ip,
                port=22,
                conn_timeout=self.configuration.ssh_conn_timeout,
                login=self.configuration.zfs_ssh_username,
                password=self.configuration.zfs_ssh_user_password,
                privatekey=self.configuration.zfs_ssh_private_key_path,
                max_size=10,
            )
        else:
            self.ssh_executor = None

    def execute(self, *cmd, **kwargs):
        """Common interface for running shell commands."""
        executor = self._execute
        if self.ssh_executor:
            executor = self.ssh_executor
        if cmd[0] == 'sudo':
            kwargs['run_as_root'] = True
            cmd = cmd[1:]
        return executor(*cmd, **kwargs)

    @utils.retry(exception.ProcessExecutionError,
                 interval=zfs_constants.RETRY_INTERVAL,
                 retries=zfs_constants.RETRIES_AMOUNT)
    def execute_with_retry(self, *cmd, **kwargs):
        """Retry wrapper over common shell interface."""
        return self.execute(*cmd, **kwargs)

    def _get_option(self, resource_name, option_name, pool_level=False):
        app = 'zpool' if pool_level else 'zfs'

        out, err = self.execute('sudo', app, 'get', option_name, resource_name)

        data = self.parse_zfs_answer(out)
        option = data[0]['VALUE']
        return option

    def parse_zfs_answer(self, string):
        lines = string.split('\n')
        if len(lines) < 2:
            return []
        keys = filter(None, lines[0].split(' '))
        data = []
        for line in lines[1:]:
            values = filter(None, line.split(' '))
            if not values:
                continue
            data.append(dict(zip(keys, values)))
        return data

    def get_zpool_option(self, zpool_name, option_name):
        return self._get_option(zpool_name, option_name, True)

    def get_zfs_option(self, dataset_name, option_name):
        return self._get_option(dataset_name, option_name, False)

    def zfs(self, *cmd, **kwargs):
        """Wrapper over 'execute' to perform ZFS operations."""
        return self.execute('sudo', 'zfs', *cmd, **kwargs)

    @utils.retry(exception.ProcessExecutionError,
                 interval=zfs_constants.RETRY_INTERVAL,
                 retries=zfs_constants.RETRIES_AMOUNT)
    def zfs_with_retry(self, *cmd, **kwargs):
        return self.zfs(*cmd, **kwargs)


@six.add_metaclass(abc.ABCMeta)
class NASHelperBase(object):
    """Base class for share helpers of 'ZFS on Linux' driver."""

    def __init__(self, configuration):
        """Init share helper.

        :param configuration: share driver 'configuration' instance
        :return: share helper instance.
        """
        self.configuration = configuration
        self.init_execute_mixin()
        self.verify_setup()
        self.zfs("share", "-a")

    @abc.abstractmethod
    def verify_setup(self):
        """Performs checks for required stuff."""

    @abc.abstractmethod
    def create_export(self, dataset_name):
        """Creates share export."""

    @abc.abstractmethod
    def get_export(self, dataset_name):
        """Gets/reads share export."""

    @abc.abstractmethod
    def remove_export(self, dataset_name):
        """Removes share export."""

    @abc.abstractmethod
    def update_access(self, dataset_name, access_rules, add_rules=None,
                      delete_rules=None):
        """Update access rules for specified ZFS dataset."""


def nfs_synchronized(f):

    def wrapped_func(self, *args, **kwargs):
        key = "nfs-%s" % args[0]

        @utils.synchronized(key)
        def source_func(self, *args, **kwargs):
            return f(self, *args, **kwargs)

        return source_func(self, *args, **kwargs)

    return wrapped_func


class NFSviaZFSHelper(ExecuteMixin, NASHelperBase):
    """Helper class for handling ZFS datasets as NFS shares.

    This helper is designed and tested with fuse version of ZFSonLinux.
    """

    DEFAULT_RULE = "sharenfs=127.0.0.1:rw,no_root_squash"

    def verify_setup(self):
        out, err = self.execute('which', 'exportfs')
        if not out:
            raise exception.ManilaException(
                _("Utility 'exportfs' is not installed."))
        try:
            self.execute('sudo', 'exportfs')
        except exception.ProcessExecutionError as e:
            msg = _("Call of 'exportfs' utility returned error: %s")
            LOG.exception(msg, e)
            raise exception.ManilaException(msg % e)

    def _get_export_location(self, dataset_name):
        """Returns export location based on dataset info."""
        mountpoint = self.get_zfs_option(dataset_name, 'mountpoint')
        export_location = "%(ip)s:%(mountpoint)s" % {
            'ip': self.configuration.zfs_share_export_ip,
            'mountpoint': mountpoint,
        }
        return export_location

    def create_export(self, dataset_name):
        self.zfs("set", self.DEFAULT_RULE, dataset_name)
        return self._get_export_location(dataset_name)

    def get_export(self, dataset_name):
        return self._get_export_location(dataset_name)

    @nfs_synchronized
    def remove_export(self, dataset_name):
        self.zfs("set", "sharenfs=off", dataset_name)

    @nfs_synchronized
    def update_access(self, dataset_name, access_rules, add_rules=None,
                      delete_rules=None):
        rules_str = "sharenfs="
        rules = []
        for rule in access_rules:
            if rule['access_type'].lower() != 'ip':
                msg = _("Only IP access type allowed for NFS protocol.")
                raise exception.InvalidShareAccess(reason=msg)
            if rule['access_level'] == constants.ACCESS_LEVEL_RW:
                rules.append(
                    "%s:rw,no_root_squash,no_all_squash" % rule['access_to'])
            elif rule['access_level'] == constants.ACCESS_LEVEL_RO:
                rules.append("%s:rw,root_squash" % rule['access_to'])
            else:
                msg = _("Unsupported access level provided - "
                        "%s.") % rule['access_level']
                raise exception.InvalidShareAccess(reason=msg)
        if rules:
            rules_str = rules_str + ' '.join(rules)
        else:
            rules_str = self.DEFAULT_RULE

        out, err = self.zfs('list', '-r', dataset_name.split('/')[0])
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] == dataset_name:
                self.zfs("set", rules_str, dataset_name)
                break
        else:
            LOG.warning(
                _LW("Dataset with '%(name)s' NAME is absent on backend. "
                    "Access rules were not applied."), {'name': dataset_name})

        # NOTE(vponomaryov): Setting of ZFS share options does not remove rules
        # that were added and then removed. So, remove them explicitly.
        for rule in delete_rules or []:
            mountpoint = self.get_zfs_option(dataset_name, 'mountpoint')
            export_location = rule['access_to'] + ':' + mountpoint
            self.execute('sudo', 'exportfs', '-u', export_location)
