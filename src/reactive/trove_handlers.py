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

from charmhelpers.core import hookenv
import charms_openstack.charm as charm
import charms.leadership as leadership
import charms.reactive as reactive

# This charm's library contains all of the handler code associated with
# the Trove Charm
from charm.openstack import exceptions
import charm.openstack.trove as trove  # noqa
from charm.openstack import utils


AMQP_DEFAULT_PORT = 5672


# Use the charms.openstack defaults for common states and hooks
charm.use_defaults(
    'charm.installed',
    'amqp.connected',
    'shared-db.connected',
    'identity-service.connected',
    'config.changed',
    'update-status',
    'upgrade-charm',
    'certificates.available',
    'cluster.available',
)


@reactive.when('leadership.is_leader')
@reactive.when('identity-service.available')
@reactive.when('amqp.available')
@reactive.when_not('is-update-status-hook')
@reactive.when_not('unit.is-departing')
def update_security_group(*args):
    """Optionally creates and updates the Trove Management Security Group.

    If a Security Group is not specified through the management-security-groups
    config option, this will create a Security Group and update its egress
    rules to allow only RabbitMQ.
    """
    config = hookenv.config('management-security-groups')
    if config:
        # Skip creating a new security group, we already have one configured.
        leadership.leader_set({'security-group-updated': True})
        return

    departing_unit = hookenv.departing_unit()
    if departing_unit:
        name = charm.get_charm_instance().configuration_class().local_unit_name
        departing_unit = departing_unit.replace('/', '-')
        if departing_unit == name:
            reactive.set_flag('unit.is-departing')
            return

    amqp = reactive.endpoint_from_flag('amqp.available')
    rabbitmq_ips = [f'{ip}/32' for ip in amqp.rabbitmq_hosts()]
    rabbitmq_port = amqp.ssl_port() or AMQP_DEFAULT_PORT

    keystone = reactive.endpoint_from_flag('identity-service.available')
    try:
        utils.update_trove_mgmt_sec_group(
            keystone, rabbitmq_ips, rabbitmq_port)
    except exceptions.DuplicateResource as ex:
        hookenv.log(
            f"The '{ex.resource_type}' to be created by this action was "
            "already duplicated. This will have to be cleaned up manually."
            "Exception: {ex}"
        )
        return
    except exceptions.APIException as ex:
        hookenv.log(
            "Encountered exception while updating the Trove management "
            f"network security group. Deferring. Exception: {ex}"
        )
        return

    leadership.leader_set({'security-group-updated': True})


def _is_departing():
    departing_unit = hookenv.departing_unit()
    if not departing_unit:
        return False

    name = charm.get_charm_instance().configuration_class().local_unit_name
    departing_unit = departing_unit.replace('/', '-')
    return departing_unit == name


@reactive.when('leadership.is_leader')
@reactive.when('identity-service.available')
@reactive.when('config.set.nexthop')
@reactive.when('config.set.management-networks')
@reactive.when('amqp.available')
@reactive.when_not('is-update-status-hook')
@reactive.when_not('unit.is-departing')
def update_rabbitmq_routes(*args):
    """Updates the Trove Management Network RabbitMQ routes.

    For each RabbitMQ related unit, we create a host route in Trove Management
    Network's subnet via the configured nexthop. Note that updates to the
    RabbitMQ IPs and routes to them will **only** apply to new Trove Database
    instances.
    """
    if _is_departing():
        reactive.set_flag('unit.is-departing')
        return

    for opt_name in ['nexthop', 'management-networks']:
        opt_value = hookenv.config(opt_name)
        if not opt_value:
            hookenv.log(f'{opt_name} config option not set.')
            return

    amqp = reactive.endpoint_from_flag('amqp.available')
    rabbitmq_ips = [f'{ip}/32' for ip in amqp.rabbitmq_hosts()]

    keystone = reactive.endpoint_from_flag('identity-service.available')
    try:
        utils.update_subnet_rabbitmq_routes(
            keystone, rabbitmq_ips, hookenv.config('nexthop'),
            hookenv.config('management-networks'))
    except exceptions.APIException as ex:
        hookenv.log(
            "Encountered exception while updating the RabbitMQ "
            f"subnet with new routes. Deferring. Exception: {ex}"
        )
        return


@reactive.when('shared-db.available')
@reactive.when('identity-service.available')
@reactive.when('amqp.available')
@reactive.when('leadership.set.security-group-updated')
@reactive.when_not('is-update-status-hook')
def render_config(*args):
    """Render the configuration for charm when all the interfaces are
    available.
    """
    with charm.provide_charm_instance() as charm_class:
        try:
            charm_class.upgrade_if_available(args)
            charm_class.render_with_interfaces(args)
            charm_class.configure_ssl()
            charm_class.assess_status()
        except exceptions.DuplicateResource as ex:
            hookenv.log(
                f"The '{ex.resource_type}' to be created by this action was "
                "already duplicated. This will have to be cleaned up manually."
                "Exception: {ex}"
            )
            return
        except exceptions.APIException as ex:
            hookenv.log(
                "Encountered exception while updating the Trove management "
                f"network security group. Deferring. Exception: {ex}"
            )
            return

    reactive.set_state('config.rendered')


# db_sync checks if sync has been done so rerunning is a noop
@reactive.when('config.rendered')
@reactive.when_not('db.synced')
def init_db():
    with charm.provide_charm_instance() as charm_class:
        charm_class.db_sync()
        charm_class.restart_all()
        charm_class.assess_status()
    reactive.set_state('db.synced')


@reactive.when('ha.connected')
@reactive.when_not('ha.available')
@reactive.when_not('is-update-status-hook')
def cluster_connected(hacluster):
    """Configure HA resources in corosync."""
    with charm.provide_charm_instance() as charm_class:
        charm_class.configure_ha_resources(hacluster)
        charm_class.assess_status()
