#    Copyright 2012 OpenStack Foundation
#    Copyright 2014 Mirantis Inc.
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

import mock
from oslo_log import log

from manila.share import driver

LOG = log.getLogger(__name__)


class FakeShareDriver(driver.ShareDriver):
    """Fake share driver."""

    def __init__(self, *args, **kwargs):
        super(FakeShareDriver, self).__init__(True, *args, **kwargs)
        self.db = mock.Mock()

        def share_network_update(*args, **kwargs):
            pass

        self.db.share_network_update = mock.Mock(
            side_effect=share_network_update)

    @property
    def driver_handles_share_servers(self):
        if not isinstance(self.configuration.safe_get(
                'driver_handles_share_servers'), bool):
            return True

    def create_snapshot(self, context, snapshot, share_server=None):
        pass

    def delete_snapshot(self, context, snapshot, share_server=None):
        pass

    def create_share(self, context, share, share_server=None):
        pass

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        pass

    def delete_share(self, context, share, share_server=None):
        pass

    def ensure_share(self, context, share, share_server=None):
        pass

    def allow_access(self, context, share, access, share_server=None):
        pass

    def deny_access(self, context, share, access, share_server=None):
        pass

    def check_for_setup_error(self):
        pass

    def get_share_stats(self, refresh=False):
        return None

    def do_setup(self, context):
        pass

    def setup_server(self, *args, **kwargs):
        pass

    def teardown_server(self, *args, **kwargs):
        pass

    def get_network_allocations_number(self):
        # NOTE(vponomaryov): Simulate drivers that use share servers and
        # do not use 'service_instance' module.
        return 2
