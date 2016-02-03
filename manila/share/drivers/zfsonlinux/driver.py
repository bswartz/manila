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

from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import timeutils

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.i18n import _LW
from manila.share import driver
from manila.share.drivers.zfsonlinux import utils as zfs_utils
from manila.share import utils as share_utils
from manila import utils


zfsonlinux_opts = [
    cfg.StrOpt(
        "zfs_share_export_ip",
        required=True,
        help="IP to be added to export location. Required."),
    cfg.ListOpt(
        "zfs_zpool_list",
        required=True,
        help="Specify list of zpools that are allowed to be used by backend. "
             "Can contain nested datasets. Examples: "
             "Without nested dataset: 'zpool_name'. "
             "With nested dataset: 'zpool_name/nested_dataset_name'. "
             "Required."),
    cfg.ListOpt(
        "zfs_dataset_creation_options",
        help="Define here list of options that should be applied "
             "for each dataset creation if needed. Example: "
             "compression=gzip,dedup=off. "
             "Note that, for secondary replicas option 'readonly' will be set "
             "to 'on' and for active replicas to 'off' in any way. "
             "Also, 'quota' will be equal to share size. Optional."),
    cfg.StrOpt(
        "zfs_dataset_name_prefix",
        default='manila_share_',
        help="Prefix to be used in each dataset name. Optional."),
    cfg.StrOpt(
        "zfs_dataset_snapshot_name_prefix",
        default='manila_share_snapshot_',
        help="Prefix to be used in each dataset snapshot name. Optional."),
    cfg.BoolOpt(
        "zfs_enable_replication",
        default=True,
        help="Defines whether this backend is allowed to support replication "
             "or not. If enabled, then option 'zfs_ssh_username' should be "
             "specified too. Optional."),
    cfg.BoolOpt(
        "zfs_use_ssh",
        default=False,
        help="Remote ZFS storage hostname that should be used for SSH'ing. "
             "Optional."),
    cfg.StrOpt(
        "zfs_ssh_username",
        help="SSH user that will be used in 2 cases: "
             "1) By manila-share service in case it is located on different "
             "host than its ZFS storage. "
             "2) By manila-share services with other ZFS backends that "
             "perform replication. "
             "It is expected that SSH'ing will be key-based, passwordless. "
             "This user should be passwordless sudoer. Optional."),
    cfg.StrOpt(
        "zfs_ssh_user_password",
        secret=True,
        help="Password for user that is used for SSH'ing ZFS storage host. "
             "Not used for replication operations. They require "
             "passwordless SSH access. Optional."),
    cfg.StrOpt(
        "zfs_ssh_private_key_path",
        help="Path to SSH private key that should be used for SSH'ing ZFS "
             "storage host. Not used for replication operations. Optional."),
    cfg.ListOpt(
        "zfs_share_helpers",
        required=True,
        default=[
            "NFS=manila.share.drivers.zfsonlinux.utils.NFSviaZFSHelper",
        ],
        help="Specify list of share export helpers for ZFS storage. "
             "It should look like following: "
             "'FOO_protocol=foo.FooClass,BAR_protocol=bar.BarClass'"
             "Required."),
    cfg.StrOpt(
        "zfs_replica_snapshot_prefix",
        required=True,
        default="tmp_snapshot_for_replication_%s",
        help="Set snapshot prefix with substitution '%s' included for "
             "usage in ZFS replication. Required."),
]

CONF = cfg.CONF
CONF.register_opts(zfsonlinux_opts)
LOG = log.getLogger(__name__)


def ensure_share_server_not_provided(f):

    def wrap(self, context, *args, **kwargs):
        server = kwargs.get('share_server')
        if server:
            raise exception.ManilaException(
                _("Share server handling is not available. "
                  "But 'share_server' was provided. '%s'. "
                  "Share network should not be used.") % server.get(
                      "id", server))
        return f(self, context, *args, **kwargs)

    return wrap


class ZFSonLinuxShareDriver(zfs_utils.ExecuteMixin, driver.ShareDriver):

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(
            [False], *args, config_opts=[zfsonlinux_opts], **kwargs)
        self.replica_snapshot_prefix = (
            self.configuration.zfs_replica_snapshot_prefix)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or 'ZFS'
        self.zpool_list = [
            pool.split('/')[0] for pool in self.configuration.zfs_zpool_list]
        self.dataset_creation_options = (
            self.configuration.zfs_dataset_creation_options)
        self.share_export_ip = self.configuration.zfs_share_export_ip
        self.private_storage = kwargs.get('private_storage')
        self._helpers = None

    def _delete_dataset_or_snapshot_with_retry(self, name):
        # NOTE(vponomaryov): it is possible to see 'dataset is busy' error
        # under the load. So, we are ok to perform retry in this case.
        self.zfs_with_retry('destroy', '-f', name)

    def _setup_helpers(self):
        self._helpers = {}
        helpers = self.configuration.zfs_share_helpers
        if helpers:
            for helper_str in helpers:
                share_proto, __, import_str = helper_str.partition('=')
                helper = importutils.import_class(import_str)
                self._helpers[share_proto.upper()] = helper(
                    self.configuration)
        else:
            raise exception.ManilaException(
                "No share helpers selected for ZFSonLinux Driver. "
                "Please specify using config option 'zfs_share_helpers'.")

    def _get_share_helper(self, share_proto):
        helper = self._helpers.get(share_proto)
        if helper:
            return helper
        else:
            raise exception.InvalidShare(
                reason=_("Wrong, unsupported or disabled protocol - "
                         "'%s'.") % share_proto)

    def do_setup(self, context):
        super(self.__class__, self).do_setup(context)
        self._setup_helpers()
        if not utils.is_valid_ip_address(self.share_export_ip, 4):
            raise exception.ManilaException(
                _("Wrong IP address provided: %s") % self.share_export_ip)

        if not self.zpool_list:
            raise exception.ManilaException(
                _("No zpools specified for usage: %s") % self.zpool_list)

        if self.configuration.zfs_use_ssh:
            self.ssh_executor('whoami')

    def _get_pools_info(self):
        pools = []
        for zpool in self.zpool_list:
            free_size = self.get_zpool_option(zpool, 'free')
            free_size = utils.translate_string_size_to_float(free_size)
            total_size = self.get_zpool_option(zpool, 'size')
            total_size = utils.translate_string_size_to_float(total_size)
            pool = {
                'pool_name': zpool,
                'total_capacity_gb': float(total_size),
                'free_capacity_gb': float(free_size),
                'reserved_percentage':
                    self.configuration.reserved_share_percentage,
            }
            if self.configuration.zfs_enable_replication:
                pool['replication_type'] = 'readable'
            pools.append(pool)
        return pools

    def _update_share_stats(self):
        """Retrieve stats info."""
        data = {
            'share_backend_name': self.backend_name,
            'storage_protocol': 'NFS',
            'reserved_percentage':
                self.configuration.reserved_share_percentage,
            'consistency_group_support': None,
            'snapshot_support': True,
            'driver_name': 'ZFS',
            'pools': self._get_pools_info(),
        }
        if self.configuration.zfs_enable_replication:
            data['replication_type'] = 'readable'
        super(self.__class__, self)._update_share_stats(data)

    def _get_share_name(self, share_id):
        prefix = self.configuration.zfs_dataset_name_prefix or ''
        return prefix + share_id.replace('-', '_')

    def _get_snapshot_name(self, snapshot_id):
        prefix = self.configuration.zfs_dataset_snapshot_name_prefix or ''
        return prefix + snapshot_id.replace('-', '_')

    def _get_dataset_creation_options(self, share, is_readonly=False):
        if not self.dataset_creation_options:
            return []
        options = []
        for option in self.dataset_creation_options:
            if any(v in option for v in ('readonly', 'sharenfs', 'sharesmb')):
                continue
            options.append(option)
        if is_readonly:
            options.append('readonly=on')
        else:
            options.append('readonly=off')
        options.append('quota=%sG' % share['size'])
        return options

    def _get_dataset_name(self, share):
        pool_name = share_utils.extract_host(share['host'], level='pool')

        # Pick pool with nested dataset name if set up
        for pool in self.configuration.zfs_zpool_list:
            pool_data = pool.split('/')
            if (pool_name == pool_data[0] and len(pool_data) > 1):
                pool_name = pool
                if pool_name[-1] == '/':
                    pool_name = pool_name[-1]
                break

        dataset_name = self._get_share_name(share['id'])
        full_dataset_name = '%(pool)s/%(dataset)s' % {
            'pool': pool_name, 'dataset': dataset_name}

        return full_dataset_name

    def _get_remote_dataset_name(self, remote_share):
        backend_name = share_utils.extract_host(
            remote_share['host'], level='host')
        ssh_cmd = '%(username)s@%(host)s' % {
            'username': self.configuration.zfs_ssh_username,
            'host': backend_name,
        }
        pool_name = share_utils.extract_host(
            remote_share['host'], level='pool')
        cmd = ('sudo', 'ssh', ssh_cmd, 'sudo', 'zfs', 'list', '-r', pool_name)

        out, err = self.execute(*cmd)

        data = self.parse_zfs_answer(out)
        for datum in data:
            if remote_share['id'].replace('-', '_') in datum['NAME']:
                return datum['NAME']
        raise exception.ManilaException(
            _("Remote host '%(host)s' does not have dataset which "
              " has str '%(str)s' in its name and located in pool "
              "'%(pool)s'.") % {
                'host': backend_name,
                'pool': pool_name,
                'str': remote_share['id'],
            })

    @ensure_share_server_not_provided
    def create_share(self, context, share, share_server=None):
        """Is called to create share."""
        options = self._get_dataset_creation_options(share, is_readonly=False)
        cmd = ['create']
        for option in options:
            cmd.extend(['-o', option])
        dataset_name = self._get_dataset_name(share)
        self.private_storage.update(
            share['id'], {
                'entity_type': 'share',
                'dataset_name': dataset_name,
                'provided_options': ' '.join(self.dataset_creation_options),
                'used_options': ' '.join(options),
            }
        )
        cmd.append(dataset_name)

        self.zfs(*cmd)

        export_location = self._get_share_helper(
            share['share_proto']).create_export(dataset_name)
        return export_location

    @ensure_share_server_not_provided
    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""
        pool_name = share_utils.extract_host(share['host'], level='pool')
        dataset_name = self.private_storage.get(share['id'], 'dataset_name')
        if not dataset_name:
            dataset_name = self._get_dataset_name(share)

        out, err = self.zfs('list', '-r', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] != dataset_name:
                continue

            # Delete dataset's snapshots first
            out, err = self.zfs('list', '-r', '-t', 'snapshot', pool_name)
            snapshots = self.parse_zfs_answer(out)
            full_snapshot_prefix = (
                dataset_name + '@' + self.replica_snapshot_prefix[0:-2])
            for snap in snapshots:
                if full_snapshot_prefix in snap['NAME']:
                    self._delete_dataset_or_snapshot_with_retry(snap['NAME'])

            self._delete_dataset_or_snapshot_with_retry(dataset_name)
            break
        else:
            LOG.warning(
                _LW("Share with '%(id)s' ID and '%(name)s' NAME is "
                    "absent on backend. Nothind has been deleted."),
                {'id': share['id'], 'name': dataset_name})
        self.private_storage.delete(share['id'])

    @ensure_share_server_not_provided
    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot."""
        dataset_name = self.private_storage.get(
            snapshot['share_id'], 'dataset_name')
        snapshot_name = self._get_snapshot_name(snapshot['id'])
        snapshot_name = dataset_name + '@' + snapshot_name
        self.private_storage.update(
            snapshot['id'], {
                'entity_type': 'snapshot',
                'snapshot_name': snapshot_name,
            }
        )
        self.zfs('snapshot', snapshot_name)

    @ensure_share_server_not_provided
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove snapshot."""
        snapshot_name = self.private_storage.get(
            snapshot['id'], 'snapshot_name')
        pool_name = snapshot_name.split('/')[0]

        out, err = self.zfs('list', '-r', '-t', 'snapshot', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] == snapshot_name:
                self._delete_dataset_or_snapshot_with_retry(snapshot_name)
                break
        else:
            LOG.warning(
                _LW("Snapshot with '%(id)s' ID and '%(name)s' NAME is "
                    "absent on backend. Nothind has been deleted."),
                {'id': snapshot['id'], 'name': snapshot_name})
        self.private_storage.delete(snapshot['id'])

    @ensure_share_server_not_provided
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        dataset_name = self._get_dataset_name(share)
        self.private_storage.update(
            share['id'], {
                'entity_type': 'share',
                'dataset_name': dataset_name,
                'provided_options': 'Cloned from source',
                'used_options': 'Cloned from source',
            }
        )
        snapshot_name = self.private_storage.get(
            snapshot['id'], 'snapshot_name')

        self.zfs(
            'clone', snapshot_name, dataset_name,
            '-o', 'quota=%sG' % share['size'],
        )

        export_location = self._get_share_helper(
            share['share_proto']).create_export(dataset_name)
        return export_location

    def get_pool(self, share):
        """Return pool name where the share resides on.

        :param share: The share hosted by the driver.
        """
        pool_name = share_utils.extract_host(share['host'], level='pool')
        return pool_name

    @ensure_share_server_not_provided
    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported.

        Driver can use this method to update the list of export locations of
        the share if it changes. To do that, you should return list with
        export locations.

        :return None or list with export locations
        """
        dataset_name = self.private_storage.get(share['id'], 'dataset_name')
        if not dataset_name:
            dataset_name = self._get_dataset_name(share)

        pool_name = share_utils.extract_host(share['host'], level='pool')
        out, err = self.zfs('list', '-r', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] == dataset_name:
                export_location = self._get_share_helper(
                    share['share_proto']).get_export(dataset_name)
                return [export_location]
        else:
            msg = _("Share with '%(id)s' ID and '%(name)s' NAME is "
                    "absent on backend. Nothing to ensure.")
            msg_data = {'id': share['id'], 'name': dataset_name}
            LOG.error(msg, msg_data)
            raise exception.ManilaException(msg % msg_data)

    def get_network_allocations_number(self):
        """ZFS does not handle networking. Return 0."""
        return 0

    @ensure_share_server_not_provided
    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share."""
        dataset_name = self._get_dataset_name(share)
        self.zfs('set', 'quota=%sG' % new_size, dataset_name)

    @ensure_share_server_not_provided
    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""
        dataset_name = self._get_dataset_name(share)
        consumed_space = self.get_zfs_option(dataset_name, 'used')
        consumed_space = utils.translate_string_size_to_float(consumed_space)
        if consumed_space >= new_size:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])
        self.zfs('set', 'quota=%sG' % new_size, dataset_name)

    @ensure_share_server_not_provided
    def create_replica(self, context, active_replica, new_replica,
                       access_rules, share_server=None):
        """Replicates the active replica to a new replica on this backend."""
        src_dataset_name = self._get_remote_dataset_name(active_replica)
        dst_dataset_name = self._get_dataset_name(new_replica)

        src_backend_name = share_utils.extract_host(
            active_replica['host'], level='host')
        dst_backend_name = share_utils.extract_host(
            new_replica['host'], level='host')

        if not src_backend_name:
            raise exception.ManilaException(
                _("Source replica backend name is unknown. Nowhere to SSH."))

        ssh_to_src_cmd = '%(username)s@%(host)s' % {
            'username': self.configuration.zfs_ssh_username,
            'host': src_backend_name,
        }
        ssh_to_dst_cmd = '%(username)s@%(host)s' % {
            'username': self.configuration.zfs_ssh_username,
            'host': dst_backend_name,
        }

        current_time = timeutils.utcnow().isoformat()
        snapshot_tag = self.replica_snapshot_prefix % current_time
        src_snapshot_name = (
            '%(dataset_name)s@%(snapshot_tag)s' % {
                'snapshot_tag': snapshot_tag,
                'dataset_name': src_dataset_name,
            }
        )
        # Save valuable data to DB
        self.private_storage.update(
            new_replica['id'], {
                'entity_type': 'replica',
                'replica_type': 'readable',
                'dataset_name': dst_dataset_name,
                'src_replica_ssh_cmd': ssh_to_src_cmd,
                'dst_replica_ssh_cmd': ssh_to_dst_cmd,
                'src_dataset_name': src_dataset_name,
                'src_snapshot_tag': snapshot_tag,
                'src_snapshot_name': src_snapshot_name,
                'provided_options': 'Cloned from source',
                'used_options': 'Cloned from source',
            }
        )

        # Create temporary snapshot. It will exist until following replica sync
        # After it new one will appear and so in loop.
        cmd = (
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'snapshot', src_snapshot_name,
        )
        self.execute(*cmd)

        # Send/receive temporary snapshot
        cmd = (
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'send', '-vD', src_snapshot_name, '|',
            'ssh', ssh_to_dst_cmd,
            'sudo', 'zfs', 'receive', '-v', dst_dataset_name,
        )
        out, err = self.execute(*cmd)
        msg = ("Info about replica '%(replica_id)s' creation is following: "
               "\n%(out)s")
        LOG.debug(msg, {'replica_id': new_replica['id'], 'out': out})

        # Make replica readonly
        self.zfs('set', 'readonly=on', dst_dataset_name)

        # Create export using original share protocol
        export_location = self._get_share_helper(
            new_replica['share_proto']).create_export(dst_dataset_name)

        # Apply access rules from original share
        self._get_share_helper(new_replica['share_proto']).update_access(
            dst_dataset_name, access_rules)

        return {
            'export_locations': [
                {'path': export_location, 'is_admin_only': False},
            ],
            'replica_state': constants.REPLICA_STATE_IN_SYNC,
            'access_rules_status': constants.REPLICA_STATE_IN_SYNC,
        }

    @ensure_share_server_not_provided
    def delete_replica(self, context, active_replica, replica,
                       share_server=None):
        """Deletes a replica. This is called on the destination backend."""
        pool_name = share_utils.extract_host(replica['host'], level='pool')
        dataset_name = self.private_storage.get(replica['id'], 'dataset_name')
        if not dataset_name:
            dataset_name = self._get_dataset_name(replica)

        # Delete dataset's snapshots first
        out, err = self.zfs('list', '-r', '-t', 'snapshot', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if dataset_name in datum['NAME']:
                self._delete_dataset_or_snapshot_with_retry(datum['NAME'])

        # Now we delete dataset itself
        out, err = self.zfs('list', '-r', pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if datum['NAME'] == dataset_name:
                self._delete_dataset_or_snapshot_with_retry(dataset_name)
                break
        else:
            LOG.warning(
                _LW("Share replica with '%(id)s' ID and '%(name)s' NAME is "
                    "absent on backend. Nothind has been deleted."),
                {'id': replica['id'], 'name': dataset_name})
        self.private_storage.delete(replica['id'])

    @ensure_share_server_not_provided
    def update_replica_state(self, context, replica, access_rules,
                             share_server=None):
        """Syncs replica and updates its 'replica_state'."""
        src_dataset_name = self.private_storage.get(
            replica['id'], 'src_dataset_name')
        src_snapshot_name = self.private_storage.get(
            replica['id'], 'src_snapshot_name')
        ssh_to_src_cmd = self.private_storage.get(
            replica['id'], 'src_replica_ssh_cmd')
        ssh_to_dst_cmd = self.private_storage.get(
            replica['id'], 'dst_replica_ssh_cmd')
        dst_dataset_name = self.private_storage.get(
            replica['id'], 'dataset_name')

        # Create temporary snapshot
        current_time = timeutils.utcnow().isoformat()
        previous_snapshot_tag = src_snapshot_name.split('@')[-1]
        snapshot_tag = self.replica_snapshot_prefix % current_time
        src_snapshot_name = src_dataset_name + '@' + snapshot_tag
        dst_snapshot_name = dst_dataset_name + '@' + snapshot_tag
        cmd = (
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'snapshot', src_snapshot_name,
        )
        self.execute(*cmd)

        # Send/receive diff between previous snapshot and last one
        cmd = (
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'send', '-vDi',
            previous_snapshot_tag, src_snapshot_name, '|',
            'ssh', ssh_to_dst_cmd,
            'sudo', 'zfs', 'receive', '-vF', dst_snapshot_name,
        )
        out, err = self.execute(*cmd)
        msg = ("Info about last replica '%(replica_id)s' sync is following: "
               "\n%(out)s")
        LOG.debug(msg, {'replica_id': replica['id'], 'out': out})

        # Update DB data that will be used on following replica sync
        self.private_storage.update(
            replica['id'], {
                'src_snapshot_tag': snapshot_tag,
                'src_snapshot_name': src_snapshot_name,
            }
        )

        # Destroy all snapshots on dst filesystem except last one
        dst_pool_name = dst_dataset_name.split('/')[0]
        out, err = self.zfs('list', '-r', '-t', 'snapshot', dst_pool_name)
        data = self.parse_zfs_answer(out)
        for datum in data:
            if (dst_dataset_name in datum['NAME'] and
                    datum['NAME'] != dst_snapshot_name):
                self._delete_dataset_or_snapshot_with_retry(datum['NAME'])

        # Destroy all snapshots on src filesystem except last one
        src_pool_name = src_snapshot_name.split('/')[0]
        cmd = (
            'ssh', ssh_to_src_cmd,
            'sudo', 'zfs', 'list', '-r', '-t', 'snapshot', src_pool_name,
        )
        out, err = self.execute(*cmd)
        data = self.parse_zfs_answer(out)
        full_src_snapshot_prefix = (
            src_dataset_name + '@' + self.replica_snapshot_prefix[0:-2])
        for datum in data:
            if (full_src_snapshot_prefix in datum['NAME'] and
                    datum['NAME'] != src_snapshot_name):
                cmd = (
                    'ssh', ssh_to_src_cmd,
                    'sudo', 'zfs', 'destroy', '-f', datum['NAME'],
                )
                self.execute_with_retry(*cmd)

        # TODO(vponomaryov): apply access rules

        # Return results
        return constants.REPLICA_STATE_IN_SYNC

    @ensure_share_server_not_provided
    def promote_replica(self, context, replica_list, replica, access_rules,
                        share_server=None):
        """Fails attempt to promote a replica to 'active' replica state."""
        msg = _("ZFS on Linux does not support 'active' replicas.")
        raise exception.ReplicationException(reason=msg)

    @ensure_share_server_not_provided
    def update_access(self, context, share, access_rules, add_rules=None,
                      delete_rules=None, share_server=None):
        """Updates access rules for given share."""
        dataset_name = self._get_dataset_name(share)
        return self._get_share_helper(share['share_proto']).update_access(
            dataset_name, access_rules, add_rules, delete_rules)

    def manage_existing(self, share, driver_options):
        """Brings an existing share under Manila management.

        If provided share is not valid, then raise a
        ManageInvalidShare exception, specifying a reason for the failure.

        The share has a share_type, and the driver can inspect that and
        compare against the properties of the referenced backend share.
        If they are incompatible, raise a
        ManageExistingShareTypeMismatch, specifying a reason for the failure.

        :param share: Share model
        :param driver_options: Driver-specific options provided by admin.
        :return: share_update dictionary with required key 'size',
                 which should contain size of the share.
        """
        # TODO(vponomaryov): implement it after
        # each backend is able to store for each its pool mapping files with
        # relation share_instance_id <-> dataset_name. That will be used for
        # getting dataset names that were managed. Also it will be possible to
        # get remote dataset_name for replication needs.
        raise NotImplementedError()

    def unmanage(self, share):
        """Removes the specified share from Manila management."""
        self.private_storage.delete(share['id'])
