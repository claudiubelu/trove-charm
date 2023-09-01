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

import functools
import ipaddress

from charmhelpers.core import hookenv
from keystoneauth1 import identity as ks_identity
from keystoneauth1 import session as ks_session
from neutronclient.v2_0 import client as neutron_client

from charm.openstack import exceptions


SYSTEM_CA_BUNDLE = '/etc/ssl/certs/ca-certificates.crt'
TROVE_MGMT_NET = 'trove-net'
TROVE_MGMT_SUBNET = 'trove-subnet'
TROVE_TAG = 'charm-trove'


def is_cidr(cidr):
    if '/' not in cidr:
        return False

    try:
        # This raises a ValueError if it's not an IP / proper length.
        ipaddress.ip_network(cidr, False)
    except ValueError:
        return False

    return True


def is_ip(ip):
    try:
        # This raises a ValueError if it's not an IP.
        ipaddress.ip_address(ip)
    except ValueError:
        return False

    return True


def api_exc_wrapper(exc_list, service, resource_type):
    def decorator(func):
        @functools.wraps(func)
        def inner(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exc_list as exc:
                raise exceptions.APIException(
                    service=service, resource_type=resource_type, exc=exc)
        return inner
    return decorator


def endpoint_type():
    if hookenv.config('use-internal-endpoints'):
        return 'internalURL'
    return 'publicURL'


def get_session_from_keystone(keystone):
    protocol = keystone.auth_protocol()
    host = keystone.auth_host()
    port = keystone.auth_port()
    auth_url = f"{protocol}://{host}:{port}/"
    auth = ks_identity.Password(
        auth_url=auth_url,
        username=keystone.service_username(),
        password=keystone.service_password(),
        project_name=keystone.service_tenant(),
        user_domain_name=keystone.service_domain(),
        project_domain_name=keystone.service_domain(),
    )
    return ks_session.Session(auth=auth, verify=SYSTEM_CA_BUNDLE)


def get_neutron_client(session):
    return neutron_client.Client(
        session=session, region_name=hookenv.config('region'),
        endpoint_type=endpoint_type(),
    )


def create_trove_mgmt_network(keystone, physical_network, cidr,
                              destination_cidr=None, nexthop=None):
    session = get_session_from_keystone(keystone)
    client = get_neutron_client(session)

    network = _get_or_create_network(client, physical_network)
    _get_or_create_subnet(
        client, network['id'], cidr, destination_cidr, nexthop)

    return network['id']


@api_exc_wrapper(exceptions.NEUTRON_EXCS, 'neutron', 'network')
def _get_or_create_network(client, physical_network):
    resp = client.list_networks(tags=TROVE_TAG)
    networks = resp.get('networks', [])
    if len(networks) > 1:
        raise exceptions.DuplicateResource('network', networks)

    # Create the network only if it doesn't exist.
    if not networks:
        return _create_network(client, physical_network)

    network = networks[0]
    set_physnet = network.get('provider:physical_network')
    if set_physnet != physical_network:
        # We can't update this field if Neutron doesn't have the
        # Multiple provider extension.
        # https://docs.openstack.org/api-ref/network/v2/index.html#multiple-provider-extension
        details = (
            'Network already exists with the "provider:physical_network" set '
            f'to {set_physnet} instead of {physical_network}.'
        )
        raise exceptions.InvalidResource('network', network['id'], details)
    return network


def _create_network(client, physical_network):
    hookenv.log(
        f"Creating Neutron network for '{physical_network}' physical network.")
    network_params = {
        'name': TROVE_MGMT_NET,
        'provider:network_type': 'flat',
        'provider:physical_network': physical_network,
        'shared': True,  # should be shared across projects / tenants.
        'description': 'Trove management network',
    }
    resp = client.create_network({'network': network_params})
    network = resp['network']

    # We cannot add tags during creation.
    client.add_tag('networks', network['id'], TROVE_TAG)

    return network


@api_exc_wrapper(exceptions.NEUTRON_EXCS, 'neutron', 'subnet')
def _get_or_create_subnet(client, network_id, cidr, dest_cidr, nexthop):
    resp = client.list_subnets(network_id=network_id)
    subnets = resp.get('subnets', [])

    # Create the subnet only if it doesn't exist.
    if not subnets:
        return _create_subnet(client, network_id, cidr, dest_cidr, nexthop)

    subnet = subnets[0]
    if ipaddress.ip_network(cidr) != ipaddress.ip_network(subnet['cidr']):
        details = (
            'Subnet already exists with a different CIDR: '
            f'{subnet["cidr"]} instead of {cidr}.'
        )
        raise exceptions.InvalidResource('subnet', subnet['id'], details)

    _update_routes(client, subnet, [dest_cidr], nexthop)

    return subnet


def _create_subnet(client, network_id, cidr, dest_cidr, nexthop):
    # We're adding a subnet for the Trove management network. The Trove
    # instance are meant to connect to RabbitMQ, they shouldn't need a gateway
    # on this  network.
    hookenv.log(f"Creating '{cidr}' subnet for '{network_id}' network.")
    subnet_params = {
        'name': f"{TROVE_MGMT_SUBNET}-v4",
        'network_id': network_id,
        'ip_version': 4,
        'cidr': cidr,
        'gateway_ip': None,
        'description': 'Trove management subnet',
    }

    if dest_cidr and nexthop:
        hookenv.log(f"Adding route {dest_cidr} via {nexthop} for "
                    f"{network_id}'s subnet.")
        subnet_params['host_routes'] = [
            {'destination': dest_cidr, 'nexthop': nexthop},
        ]

    resp = client.create_subnet({'subnets': [subnet_params]})
    return resp['subnets'][0]


def _routes_exist(old_routes, destinations, nexthop):
    # The routes exist if both lists have the same length, and the destinations
    # and nexthops match.
    if len(old_routes) != len(destinations):
        return False

    for route in old_routes:
        if route['nexthop'] != nexthop:
            return False

        if route['destination'] not in destinations:
            return False

    return True


def _update_routes(client, subnet, destinations, nexthop):
    if _routes_exist(subnet['host_routes'], destinations, nexthop):
        # Routes already exist. Nothing to do in this case.
        hookenv.log(
            f"Subnet {subnet['id']} already has the routes: {destinations} "
            f"via {nexthop}.")
        return

    hookenv.log(
        f"Adding routes to subnet '{subnet['id']}': {destinations} via "
        f"{nexthop}.")

    host_routes = [
        {'destination': dest, 'nexthop': nexthop} for dest in destinations
    ]
    params = {'host_routes': host_routes}

    # This will also override existing routes.
    client.update_subnet(subnet['id'], {'subnet': params})
