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

import unittest
from unittest import mock

from charmhelpers.core import hookenv
from keystoneauth1 import exceptions as ks_exc

from charm.openstack import exceptions
from charm.openstack import utils


class TestUtils(unittest.TestCase):

    @mock.patch.object(hookenv, 'config')
    def test_endpoint_type(self, mock_config):
        mock_config.return_value = False
        self.assertEquals('publicURL', utils.endpoint_type())

        mock_config.return_value = True
        self.assertEquals('internalURL', utils.endpoint_type())

    @mock.patch.object(utils, 'ks_session')
    @mock.patch.object(utils, 'ks_identity')
    def test_get_session_from_keystone(self, mock_identity, mock_session):
        mock_ks = mock.Mock()

        result = utils.get_session_from_keystone(mock_ks)

        self.assertEqual(mock_session.Session.return_value, result)
        expected_auth_url = "%s://%s:%s/" % (
            mock_ks.auth_protocol.return_value,
            mock_ks.auth_host.return_value,
            mock_ks.auth_port.return_value,
        )
        mock_identity.Password.assert_called_once_with(
            auth_url=expected_auth_url,
            user_domain_name=mock_ks.service_domain.return_value,
            username=mock_ks.service_username.return_value,
            password=mock_ks.service_password.return_value,
            project_domain_name=mock_ks.service_domain.return_value,
            project_name=mock_ks.service_tenant.return_value,
        )
        mock_session.Session.assert_called_once_with(
            auth=mock_identity.Password.return_value,
            verify=utils.SYSTEM_CA_BUNDLE,
        )

    @mock.patch.object(utils, 'endpoint_type')
    @mock.patch.object(hookenv, 'config')
    @mock.patch.object(utils, 'neutron_client')
    def test_get_neutron_client(self, mock_nc, mock_config, mock_endpoint):
        client = utils.get_neutron_client(mock.sentinel.session)

        self.assertEqual(mock_nc.Client.return_value, client)
        mock_config.assert_called_once_with('region')
        mock_nc.Client.assert_called_once_with(
            session=mock.sentinel.session,
            region_name=mock_config.return_value,
            endpoint_type=mock_endpoint.return_value,
        )

    @mock.patch.object(utils, '_get_or_create_subnet')
    @mock.patch.object(utils, '_get_or_create_network')
    @mock.patch.object(utils, 'get_neutron_client')
    @mock.patch.object(utils, 'get_session_from_keystone')
    def test_create_trove_mgmt_network(
            self, mock_get_sess, mock_get_nc, mock_get_net, mock_get_subnet):
        mock_get_net.return_value = {'id': mock.sentinel.id}

        net_id = utils.create_trove_mgmt_network(
            mock.sentinel.keystone,
            mock.sentinel.physnet,
            mock.sentinel.net_type,
            mock.sentinel.cidr,
            mock.sentinel.segmentation_id,
            mock.sentinel.dest_cidr,
            mock.sentinel.nexthop,
        )

        self.assertEqual(mock.sentinel.id, net_id)
        mock_get_sess.assert_called_once_with(mock.sentinel.keystone)
        mock_client = mock_get_nc.return_value
        mock_get_nc.assert_called_once_with(mock_get_sess.return_value)
        mock_get_net.assert_called_once_with(
            mock_client, mock.sentinel.physnet, mock.sentinel.net_type,
            mock.sentinel.segmentation_id)
        mock_get_subnet.assert_called_once_with(
            mock_client, mock.sentinel.id, mock.sentinel.cidr,
            mock.sentinel.dest_cidr, mock.sentinel.nexthop)

    def test_get_or_create_network_decorator(self):
        mock_client = mock.Mock()
        mock_client.list_networks.side_effect = ks_exc.catalog.EndpointNotFound

        self.assertRaises(
            exceptions.APIException,
            utils._get_or_create_network,
            mock_client,
            mock.sentinel.physnet,
            mock.sentinel.net_type,
            mock.sentinel.segmentation_id,
        )

    def test_get_or_create_network_exc(self):
        mock_client = mock.Mock()
        mock_client.list_networks.return_value = {
            'networks': [mock.sentinel.network] * 2,
        }

        self.assertRaises(
            exceptions.DuplicateResource,
            utils._get_or_create_network,
            mock_client,
            mock.sentinel.physnet,
            mock.sentinel.net_type,
            mock.sentinel.segmentation_id,
        )
        mock_client.list_networks.assert_called_once_with(tags=utils.TROVE_TAG)

        fake_net = {
            'id': mock.sentinel.id,
            'provider:physical_network': mock.sentinel.physnet,
            'provider:network_type': mock.sentinel.net_type,
            'provider:segmentation_id': mock.sentinel.segmentation_id,
        }
        mock_client.list_networks.return_value = {'networks': [fake_net]}

        # Replace expected field values with a bad value and expect an
        # InvalidResource exception to be raised.
        for key in fake_net.keys():
            if key == 'id':
                continue

            val = fake_net[key]
            fake_net[key] = mock.sentinel.bad_value

            self.assertRaises(
                exceptions.InvalidResource,
                utils._get_or_create_network,
                mock_client,
                mock.sentinel.physnet,
                mock.sentinel.net_type,
                mock.sentinel.segmentation_id,
            )

            fake_net[key] = val

    @mock.patch.object(utils, '_create_network')
    def test_get_or_create_network(self, mock_create_net):
        mock_client = mock.Mock()
        fake_net = {
            'id': mock.sentinel.id,
            'provider:physical_network': mock.sentinel.physnet,
            'provider:network_type': mock.sentinel.net_type,
            'provider:segmentation_id': mock.sentinel.segmentation_id,
        }
        mock_client.list_networks.return_value = {'networks': [fake_net]}

        network = utils._get_or_create_network(
            mock_client, mock.sentinel.physnet, mock.sentinel.net_type,
            mock.sentinel.segmentation_id)

        self.assertEqual(fake_net, network)

        mock_client.list_networks.return_value = {'networks': []}
        network = utils._get_or_create_network(
            mock_client, mock.sentinel.physnet, mock.sentinel.net_type,
            mock.sentinel.segmentation_id)
        self.assertEqual(mock_create_net.return_value, network)
        mock_create_net.assert_called_once_with(
            mock_client, mock.sentinel.physnet, mock.sentinel.net_type,
            mock.sentinel.segmentation_id)

    def test_create_network(self):
        mock_client = mock.Mock()
        fake_network = {'id': mock.sentinel.net_id}
        mock_client.create_network.return_value = {'network': fake_network}

        network = utils._create_network(
            mock_client, mock.sentinel.physnet, 'vlan', mock.sentinel.vlan_id)

        self.assertEqual(fake_network, network)
        expected_params = {
            'name': utils.TROVE_MGMT_NET,
            'provider:network_type': 'vlan',
            'provider:physical_network': mock.sentinel.physnet,
            'provider:segmentation_id': mock.sentinel.vlan_id,
            'shared': True,
            'description': 'Trove management network',
        }
        mock_client.create_network.assert_called_once_with(
            {'network': expected_params})
        mock_client.add_tag.assert_called_once_with(
            'networks', mock.sentinel.net_id, utils.TROVE_TAG)

    def test_get_or_create_subnet_exc(self):
        mock_client = mock.Mock()
        fake_subnet = {'id': mock.sentinel.id, 'cidr': '192.168.1.0/24'}
        mock_client.list_subnets.return_value = {'subnets': [fake_subnet]}

        self.assertRaises(
            exceptions.InvalidResource,
            utils._get_or_create_subnet,
            mock_client,
            mock.sentinel.net_id,
            '10.10.10.0/24',
            mock.sentinel.dest_cidr,
            mock.sentinel.nexthop,
        )
        mock_client.list_subnets.assert_called_once_with(
            network_id=mock.sentinel.net_id)

    @mock.patch.object(utils, '_update_routes')
    @mock.patch.object(utils, '_create_subnet')
    def test_get_or_create_subnet(self, mock_create_subnet,
                                  mock_update_routes):
        mock_client = mock.Mock()
        fake_cidr = '192.168.1.0/24'
        fake_subnet = {'cidr': fake_cidr}

        mock_client.list_subnets.return_value = {
            'subnets': [fake_subnet],
        }
        subnet = utils._get_or_create_subnet(
            mock_client, mock.sentinel.net_id, fake_cidr,
            mock.sentinel.dest_cidr, mock.sentinel.nexthop)
        self.assertEqual(fake_subnet, subnet)
        mock_update_routes.assert_called_once_with(
            mock_client, subnet, [mock.sentinel.dest_cidr],
            mock.sentinel.nexthop)

        mock_client.list_subnets.return_value = {'subnets': []}
        subnet = utils._get_or_create_subnet(
            mock_client, mock.sentinel.net_id, mock.sentinel.cidr,
            mock.sentinel.dest_cidr, mock.sentinel.nexthop)
        self.assertEqual(mock_create_subnet.return_value, subnet)
        mock_create_subnet.assert_called_once_with(
            mock_client, mock.sentinel.net_id, mock.sentinel.cidr,
            mock.sentinel.dest_cidr, mock.sentinel.nexthop)

    def test_create_subnet(self):
        mock_client = mock.Mock()
        mock_client.create_subnet.return_value = {
            'subnets': [mock.sentinel.subnet],
        }

        subnet = utils._create_subnet(
            mock_client, mock.sentinel.net_id, mock.sentinel.cidr,
            mock.sentinel.dest_cidr, mock.sentinel.nexthop)

        self.assertEqual(mock.sentinel.subnet, subnet)
        expected_route = {
            'destination': mock.sentinel.dest_cidr,
            'nexthop': mock.sentinel.nexthop,
        }
        expected_params = {
            'name': f"{utils.TROVE_MGMT_SUBNET}-v4",
            'network_id': mock.sentinel.net_id,
            'ip_version': 4,
            'cidr': mock.sentinel.cidr,
            'gateway_ip': None,
            'description': 'Trove management subnet',
            'host_routes': [expected_route],
        }
        mock_client.create_subnet.assert_called_once_with(
            {'subnets': [expected_params]})

    def test_routes_exist_different_len(self):
        result = utils._routes_exist(
            [], [mock.sentinel.route], mock.sentinel.nexthop)

        self.assertFalse(result)

    def test_routes_exist_different_nexthop(self):
        old_route = {'nexthop': mock.sentinel.otherhop}

        result = utils._routes_exist(
            [old_route], [mock.sentinel.route], mock.sentinel.nexthop)

        self.assertFalse(result)

    def test_routes_exist_different_destination(self):
        old_route = {
            'destination': mock.sentinel.other_route,
            'nexthop': mock.sentinel.nexthop,
        }

        result = utils._routes_exist(
            [old_route], [mock.sentinel.route], mock.sentinel.nexthop)

        self.assertFalse(result)

    def test_routes_exist(self):
        old_route = {
            'destination': mock.sentinel.route,
            'nexthop': mock.sentinel.nexthop,
        }

        result = utils._routes_exist(
            [old_route], [mock.sentinel.route], mock.sentinel.nexthop)

        self.assertTrue(result)

    def test_update_routes_already_exists(self):
        routes = [
            {'destination': mock.sentinel.dest, 'nexthop': mock.sentinel.hop},
        ]
        subnet = {
            'id': mock.sentinel.id,
            'name': mock.sentinel.name,
            'host_routes': routes,

        }
        mock_client = mock.Mock()

        utils._update_routes(mock_client, subnet, [mock.sentinel.dest],
                             mock.sentinel.hop)

        mock_client.update_subnet.assert_not_called()

    def test_update_routes(self):
        mock_client = mock.Mock()
        existing_route = {
            'destination': mock.sentinel.dest_cidr,
            'nexthop': mock.sentinel.otherhop,
        }
        subnet = {
            'name': mock.sentinel.name,
            'id': mock.sentinel.id,
            'host_routes': [existing_route],
        }

        utils._update_routes(mock_client, subnet, [mock.sentinel.dest_cidr],
                             mock.sentinel.nexthop)

        # Assert that the old route has been removed.
        expected_routes = {
            'host_routes': [{
                'destination': mock.sentinel.dest_cidr,
                'nexthop': mock.sentinel.nexthop,
            }],
        }
        mock_client.update_subnet.assert_called_once_with(
            mock.sentinel.id, {'subnet': expected_routes})

    @mock.patch.object(utils, '_get_or_create_sec_group')
    @mock.patch.object(utils, 'get_neutron_client')
    @mock.patch.object(utils, 'get_session_from_keystone')
    def test_get_trove_mgmt_sec_group(
            self, mock_get_sess, mock_get_nc, mock_get_sg):
        mock_get_sg.return_value = {'id': mock.sentinel.group_id}

        sec_group_id = utils.get_trove_mgmt_sec_group(mock.sentinel.keystone)

        self.assertEqual(mock.sentinel.group_id, sec_group_id)
        mock_get_sess.assert_called_once_with(mock.sentinel.keystone)
        mock_client = mock_get_nc.return_value
        mock_get_nc.assert_called_once_with(mock_get_sess.return_value)
        mock_get_sg.assert_called_once_with(mock_client)

    @mock.patch.object(utils, '_create_sec_group_rule')
    @mock.patch.object(utils, '_get_or_create_sec_group')
    @mock.patch.object(utils, 'get_neutron_client')
    @mock.patch.object(utils, 'get_session_from_keystone')
    def test_update_trove_mgmt_sec_group(
            self, mock_get_sess, mock_get_nc, mock_get_sg,
            mock_create_sg_rule):
        # The tested function should:
        # - remove a rule that is no longer needed.
        # - remove a rule with a different port and add a new one.
        # - add a new rule for the new IP.
        # - leave the rest of the rules untouched.
        old_sec_group_rules = [
            {
                'id': mock.sentinel.id1,
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip1,
                'port_range_min': mock.sentinel.port,
            },
            {
                'id': mock.sentinel.id2,
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip2,
                'port_range_min': mock.sentinel.otherport,
            },
            {
                'id': mock.sentinel.id3,
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip3,
                'port_range_min': mock.sentinel.port,
            },
            {
                'id': mock.sentinel.id4,
                'direction': 'ingress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip4,
            },
            {
                'id': mock.sentinel.id5,
                'direction': 'egress',
                'ethertype': 'IPv6',
                'protocol': 'tcp',
                'remote_ip_prefix': mock.sentinel.ip5,
            },
            {
                'id': mock.sentinel.id6,
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'udp',
                'remote_ip_prefix': mock.sentinel.ip6,
            },
        ]
        mock_get_sg.return_value = {
            'id': mock.sentinel.group_id,
            'security_group_rules': old_sec_group_rules,
        }
        new_rabbitmq_ips = [mock.sentinel.ip2, mock.sentinel.ip3,
                            mock.sentinel.ipnew]

        sec_group_id = utils.update_trove_mgmt_sec_group(
            mock.sentinel.keystone,
            new_rabbitmq_ips,
            mock.sentinel.port,
        )

        self.assertEqual(mock.sentinel.group_id, sec_group_id)
        mock_get_sess.assert_called_once_with(mock.sentinel.keystone)
        mock_client = mock_get_nc.return_value
        mock_get_nc.assert_called_once_with(mock_get_sess.return_value)
        mock_get_sg.assert_called_once_with(mock_client)
        mock_create_sg_rule.assert_has_calls([
            mock.call(mock_client, mock.sentinel.group_id, 'egress', 'tcp',
                      mock.sentinel.ip2, mock.sentinel.port),
            mock.call(mock_client, mock.sentinel.group_id, 'egress', 'tcp',
                      mock.sentinel.ipnew, mock.sentinel.port),
        ])
        mock_client.delete_security_group_rule.assert_has_calls([
            mock.call(mock.sentinel.id1),
            mock.call(mock.sentinel.id2),
        ])

    def test_get_or_create_sec_group_exc(self):
        mock_client = mock.Mock()
        mock_client.list_security_groups.return_value = {
            'security_groups': [mock.sentinel.sec_group] * 2,
        }

        self.assertRaises(
            exceptions.DuplicateResource,
            utils._get_or_create_sec_group,
            mock_client,
        )
        mock_client.list_security_groups.assert_called_once_with(
            tags=utils.TROVE_TAG)

    @mock.patch.object(utils, '_create_sec_group')
    def test_get_or_create_sec_group(self, mock_create_sec_group):
        mock_client = mock.Mock()
        mock_client.list_security_groups.return_value = {
            'security_groups': [mock.sentinel.group],
        }

        sec_group = utils._get_or_create_sec_group(mock_client)

        self.assertEqual(mock.sentinel.group, sec_group)

        mock_client.list_security_groups.return_value = {
            'security_groups': [],
        }
        fake_sec_group_rule = {'id': mock.sentinel.rule_id}
        fake_sec_group = {
            'security_group_rules': [fake_sec_group_rule] * 2,
        }
        mock_create_sec_group.return_value = fake_sec_group

        sec_group = utils._get_or_create_sec_group(mock_client)

        self.assertEqual(fake_sec_group, sec_group)
        self.assertListEqual([], fake_sec_group['security_group_rules'])
        mock_client.delete_security_group_rule.assert_has_calls(
            [mock.call(mock.sentinel.rule_id)] * 2)
        mock_create_sec_group.assert_called_once_with(mock_client)

    def test_create_sec_group(self):
        mock_client = mock.Mock()
        fake_sec_group = {'id': mock.sentinel.sec_group_id}
        mock_client.create_security_group.return_value = {
            'security_group': fake_sec_group}

        sec_group = utils._create_sec_group(mock_client)

        self.assertEqual(fake_sec_group, sec_group)
        expected_params = {
            'name': utils.TROVE_MGMT_SG,
            'description': 'Trove management network security group',
        }
        mock_client.create_security_group.assert_called_once_with(
            {'security_group': expected_params})
        mock_client.add_tag.assert_called_once_with(
            'security-groups', mock.sentinel.sec_group_id, utils.TROVE_TAG)

    def test_create_sec_group_rule(self):
        mock_client = mock.Mock()

        utils._create_sec_group_rule(
            mock_client,
            mock.sentinel.sec_group_id,
            mock.sentinel.direction,
            mock.sentinel.protocol,
            mock.sentinel.remote_ip,
            mock.sentinel.port_min,
        )

        expected_params = {
            'security_group_id': mock.sentinel.sec_group_id,
            'direction': mock.sentinel.direction,
            'protocol': mock.sentinel.protocol,
            'ethertype': 'IPv4',
            'remote_ip_prefix': mock.sentinel.remote_ip,
            'port_range_min': mock.sentinel.port_min,
            'port_range_max': mock.sentinel.port_min,
        }
        mock_client.create_security_group_rule.assert_called_once_with(
            {'security_group_rule': expected_params})
