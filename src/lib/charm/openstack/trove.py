import collections
import os

import charmhelpers.core.hookenv as hookenv
import charms_openstack.charm
import charms_openstack.ip as os_ip
import charms.reactive as reactive

from charm.openstack import utils


PACKAGES = [
    'trove-api',
    'trove-conductor',
    'trove-taskmanager',
]

TROVE_SERVICES = [
    'trove-api',
    'trove-conductor',
    'trove-taskmanager',
]

TROVE_API_PORT = 8779
TROVE_DIR = '/etc/trove'
TROVE_CONF = os.path.join(TROVE_DIR, 'trove.conf')
TROVE_GUESTAGENT_CONF = os.path.join(TROVE_DIR, 'trove-guestagent.conf')
TROVE_PASTE_API = os.path.join(TROVE_DIR, 'api-paste.ini')

# select the default release function
charms_openstack.charm.use_defaults('charm.default-select-release')


@charms_openstack.adapters.config_property
def trove_security_group(cls):
    """Returns the Trove Management Network Security Group ID.

    Config property adapter which returns the Security Group ID set in the
    `management-security-groups` config option, or the ID of the Security
    Group created by the Trove charm (tagged with `charm-trove`).
    """
    config = hookenv.config('management-security-groups')
    if config:
        return config

    # If the config option was not set, use the Security Group created by
    # the charm.
    keystone = reactive.endpoint_from_flag('identity-service.available')
    return utils.get_trove_mgmt_sec_group(keystone)


class TroveCharm(charms_openstack.charm.HAOpenStackCharm):

    # Internal name of charm
    service_name = name = 'trove'

    # First release supported
    release = 'yoga'

    # List of packages to install for this charm
    packages = PACKAGES

    # The base class was not updated to support only Python3. If we don't
    # specify this, python-memcache would be installed instead of
    # python3-memcache, which would result in an error in the install phase.
    python_version = 3

    api_ports = {
        'trove-api': {
            os_ip.PUBLIC: TROVE_API_PORT,
            os_ip.ADMIN: TROVE_API_PORT,
            os_ip.INTERNAL: TROVE_API_PORT,
        }
    }

    service_type = 'trove'
    default_service = 'trove-api'
    services = ['haproxy'] + TROVE_SERVICES
    sync_cmd = ['trove-manage', 'db_sync']

    required_relations = ['shared-db', 'amqp', 'identity-service']

    # Mandatory config options needed by Trove to run.
    mandatory_config = ['management-networks']

    restart_map = {
        TROVE_CONF: services,
        TROVE_GUESTAGENT_CONF: services,
        TROVE_PASTE_API: [default_service],
    }

    ha_resources = ['vips', 'haproxy']

    # Package for release version detection
    release_pkg = 'trove-common'

    # Package codename map for trove-common
    package_codenames = {
        'trove-common': collections.OrderedDict([
            ('17', 'yoga'),
            ('18', 'zed'),
            ('19', 'antelope'),
        ]),
    }

    # The group owning the config files.
    group = "trove"

    @property
    def public_url(self):
        """Return the public endpoint URL for the default service as specified
        in the self.default_service attribute
        """
        return f"{super().public_url}/v1.0/$(tenant_id)s"

    @property
    def admin_url(self):
        """Return the admin endpoint URL for the default service as specificed
        in the self.default_service attribute
        """
        return f"{super().admin_url}/v1.0/$(tenant_id)s"

    @property
    def internal_url(self):
        """Return the internal internal endpoint URL for the default service as
        specificated in the self.default_service attribtue
        """
        return f"{super().internal_url}/v1.0/$(tenant_id)s"

    def get_amqp_credentials(self):
        """Provide the default AMQP username and vhost as a tuple.

        : returns (username, host): two strings to send to the AMQP provider.
        """
        return (self.config['rabbit-user'], self.config['rabbit-vhost'])

    def get_database_setup(self):
        """Provide the default database credentials as a list of 3-tuples.

        This is used when using the default handlers for the shared-db service
        and provides the (db, db_user, ip) for each database as a list.

        :returns [{'database': ...}, ...]: credentials for a Trove database.
        """
        return [
            {
                'database': self.config['database'],
                'username': self.config['database-user'],
                'hostname': hookenv.unit_private_ip(),
            },
        ]
