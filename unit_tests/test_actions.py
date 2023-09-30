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

from actions import actions
from charm.openstack import exceptions
from unit_tests import base


class TestCreateMgmtNetworkAction(base.TestBase):

    def setUp(self):
        super().setUp()

        self._hookenv = self._patch(actions, 'hookenv')
        self._reactive = self._patch(actions, 'reactive')
        self._args = {
            'physical-network': mock.sentinel.physnet,
            'network-type': 'vlan',
            'cidr': '10.10.10.0/24',
            'segmentation-id': 1000,
            'destination-cidr': '10.10.9.0/24',
            'nexthop': '10.10.10.1',
        }
        self._hookenv.action_get.return_value = self._args

    def test_create_mgmt_net_not_leader(self):
        self._reactive.is_flag_set.return_value = False

        result = actions.create_mgmt_network_action()

        self.assertEqual(self._hookenv.action_fail.return_value, result)
        self._reactive.is_flag_set.assert_called_once_with(
            'leadership.is_leader')
        self._reactive.all_flags_set.assert_not_called()

    def test_create_mgmt_net_not_all_flags(self):
        self._reactive.all_flags_set.return_value = False

        result = actions.create_mgmt_network_action()

        self.assertEqual(self._hookenv.action_fail.return_value, result)
        self._reactive.all_flags_set.assert_called_once_with(
            *actions.REQUIRED_FLAGS)
        self._hookenv.actions_get.assert_not_called()

    def test_create_mgmt_net_fail_validation(self):
        # Either both destination-cidr and nexthop must exist, or neither.
        self._args.pop('destination-cidr')

        result = actions.create_mgmt_network_action()

        self.assertEqual(self._hookenv.action_fail.return_value, result)
        self._reactive.all_flags_set.assert_called_once_with(
            *actions.REQUIRED_FLAGS)

    @mock.patch.object(actions.utils, 'create_trove_mgmt_network')
    def test_create_mgmt_net_no_extra_args(self, mock_create_net):
        self._args.pop('destination-cidr')
        self._args.pop('nexthop')

        result = actions.create_mgmt_network_action()

        self.assertIsNone(result)
        self._reactive.endpoint_from_flag.assert_called_once_with(
            'identity-service.available')
        mock_create_net.assert_called_once_with(
            self._reactive.endpoint_from_flag.return_value,
            mock.sentinel.physnet,
            self._args['network-type'],
            self._args['cidr'],
            self._args['segmentation-id'],
            None,
            None,
        )

    @mock.patch.object(actions.utils, 'create_trove_mgmt_network')
    def test_create_mgmt_net_exc(self, mock_create_net):
        for exc in [exceptions.DuplicateResource, exceptions.InvalidResource,
                    exceptions.APIException]:
            mock_create_net.side_effect = exc

            result = actions.create_mgmt_network_action()

            self.assertEqual(self._hookenv.action_fail.return_value, result)
            mock_create_net.assert_called_with(
                self._reactive.endpoint_from_flag.return_value,
                mock.sentinel.physnet,
                self._args['network-type'],
                self._args['cidr'],
                self._args['segmentation-id'],
                self._args['destination-cidr'],
                self._args['nexthop'],
            )

    def test_validate_create_mgmt_net_action_args_missing(self):
        for key in ['destination-cidr', 'nexthop']:
            value = self._args.pop(key)

            result = actions._validate_create_mgmt_net_action_args(self._args)
            self.assertEqual(self._hookenv.action_fail.return_value, result,
                             f"Failed for key '{key}'.")

            self._args[key] = value

    def test_validate_create_mgmt_net_action_args_invalid(self):
        for key in ['network-type', 'cidr', 'destination-cidr', 'nexthop']:
            value = self._args.pop(key)
            self._args[key] = 'foo'

            result = actions._validate_create_mgmt_net_action_args(self._args)
            self.assertEqual(self._hookenv.action_fail.return_value, result,
                             f"Failed for key '{key}'.")

            self._args[key] = value

        self._args['network-type'] = 'flat'
        result = actions._validate_create_mgmt_net_action_args(self._args)
        self.assertEqual(self._hookenv.action_fail.return_value, result,
                         "Failed for network-type 'flat'.")

        self._args['network-type'] = 'vlan'
        self._args['segmentation-id'] = 0
        result = actions._validate_create_mgmt_net_action_args(self._args)
        self.assertEqual(self._hookenv.action_fail.return_value, result,
                         "Failed for network-type 'vlan'.")
