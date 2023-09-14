# Copyright 2023 Cloudbase Solutions
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from charmhelpers.core import hookenv
import charms_openstack.charm as charm
import charms_openstack.test_utils as test_utils

from charm.openstack import exceptions
import reactive.trove_handlers as handlers
from unit_tests import base


class TestRegisteredHooks(test_utils.TestRegisteredHooks):

    def test_hooks(self):
        defaults = [
            'charm.installed',
            'amqp.connected',
            'shared-db.connected',
            'identity-service.connected',
            'config.changed',
            'update-status',
            'upgrade-charm',
            'certificates.available',
        ]
        hook_set = {
            'when': {
                'update_security_group': (
                    'leadership.is_leader',
                    'identity-service.available',
                    'amqp.available',
                ),
                'render_config': (
                    'shared-db.available',
                    'identity-service.available',
                    'amqp.available',
                    'leadership.set.security-group-updated',
                ),
                'init_db': ('config.rendered',),
                'cluster_connected': ('ha.connected',),
            },
            'when_not': {
                'update_security_group': (
                    'is-update-status-hook',
                    'unit.is-departing',
                ),
                'render_config': ('is-update-status-hook',),
                'init_db': ('db.synced',),
                'cluster_connected': ('ha.available', 'is-update-status-hook'),
            },
            'hook': {
                'upgrade_charm': ('upgrade-charm',),
            },
        }
        # test that the hooks were registered via the
        # reactive.octavia_handlers
        self.registered_hooks_test_helper(handlers, hook_set, defaults)


class TestTroveHandlers(base.TestBase):

    def setUp(self):
        super().setUp()

        self._hookenv = self._patch(handlers, 'hookenv')
        self._reactive = self._patch(handlers, 'reactive')
        self._leadership = self._patch(handlers, 'leadership')
        self._trove_charm = mock.Mock()

        provide_charm_inst = self._patch(handlers.charm,
                                         'provide_charm_instance')
        provide_charm_inst().__enter__.return_value = self._trove_charm
        provide_charm_inst().__exit__.return_value = None

    def test_update_security_group_skip(self):
        handlers.update_security_group()

        self._hookenv.config.assert_called_once_with(
            'management-security-groups')
        self._leadership.leader_set.assert_called_once_with(
            {'security-group-updated': True})
        self._reactive.endpoint_from_flag.assert_not_called()

    def test_update_security_group_departing(self):
        self._hookenv.config.return_value = ""
        hookenv.local_unit.return_value = 'foo/0'
        self._hookenv.departing_unit.return_value = 'foo/0'

        handlers.update_security_group()

        self._reactive.set_flag.assert_called_once_with('unit.is-departing')
        self._reactive.endpoint_from_flag.assert_not_called()

    def test_update_security_group(self):
        self._test_update_security_group()

    def test_update_security_group_duplicate(self):
        self._test_update_security_group(
            side_effect=exceptions.DuplicateResource)

    def test_update_security_group_api_exc(self):
        self._test_update_security_group(
            side_effect=exceptions.APIException)

    @mock.patch.object(handlers.utils, 'update_trove_mgmt_sec_group')
    def _test_update_security_group(self, mock_update_trove_sg,
                                    side_effect=None):
        self._hookenv.config.return_value = ""
        mock_amqp = mock.Mock()
        mock_keystone = mock.Mock()
        self._reactive.endpoint_from_flag.side_effect = [
            mock_amqp, mock_keystone]
        mock_amqp.rabbitmq_hosts.return_value = ['10.10.10.10']
        mock_amqp.ssl_port.return_value = 9999
        mock_update_trove_sg.side_effect = side_effect

        handlers.update_security_group()

        self._reactive.endpoint_from_flag.assert_has_calls([
            mock.call('amqp.available'),
            mock.call('identity-service.available')])
        mock_update_trove_sg.assert_called_once_with(
            mock_keystone, ['10.10.10.10/32'], 9999)
        if side_effect:
            self._hookenv.log.assert_called_once()
        else:
            self._leadership.leader_set.assert_called_once_with(
                {'security-group-updated': True})

    def test_render_config(self):
        handlers.render_config(mock.sentinel.arg)

        self._trove_charm.upgrade_if_available.assert_called_once_with(
            (mock.sentinel.arg,))
        self._trove_charm.render_with_interfaces.assert_called_once_with(
            (mock.sentinel.arg,))
        self._trove_charm.assess_status.assert_called_once_with()
        self._reactive.set_state.assert_called_once_with('config.rendered')

    def test_render_config_duplicate(self):
        self._test_render_config(side_effect=exceptions.DuplicateResource)

    def test_render_config_api_exc(self):
        self._test_render_config(side_effect=exceptions.APIException)

    def _test_render_config(self, side_effect):
        self._trove_charm.upgrade_if_available.side_effect = side_effect
        handlers.render_config()

        self._hookenv.log.assert_called_once()
        self._reactive.set_state.assert_not_called()
