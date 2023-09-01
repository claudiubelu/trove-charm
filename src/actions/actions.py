#!/usr/bin/env python3
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

import os
import subprocess
import sys

# Load modules from $CHARM_DIR/lib
sys.path.append('lib')

from charms.layer import basic
basic.bootstrap_charm_deps()
basic.init_config_states()

from charms import reactive
from charmhelpers.core import hookenv
import requests

from charm.openstack import exceptions
from charm.openstack import utils

REQUIRED_FLAGS = ['identity-service.available']


def create_mgmt_network_action(*args):
    """Creates Neutron Management Network for Trove instances."""
    if not reactive.is_flag_set('leadership.is_leader'):
        return hookenv.action_fail('action must be run on the leader unit.')

    if not reactive.all_flags_set(*REQUIRED_FLAGS):
        return hookenv.action_fail(
            'all required relations are not available yet, rerun action when '
            'deployment is complete.')

    action_args = hookenv.action_get()
    failure = _validate_create_mgmt_net_action_args(action_args)
    if failure:
        return failure

    keystone = reactive.endpoint_from_flag('identity-service.available')
    try:
        utils.create_trove_mgmt_network(
            keystone,
            action_args['physical-network'],
            action_args['cidr'],
            action_args.get('destination-cidr'),
            action_args.get('nexthop'),
        )
    except exceptions.DuplicateResource as ex:
        msg = (
            f"The '{ex.resource_type}' to be created by this action was "
            "already duplicated. This will have to be cleaned up manually."
        )
        hookenv.log(f'{msg} Exception: {ex}')
        return hookenv.action_fail(
            f'{msg} Check the unit logs for more details.')
    except exceptions.InvalidResource as ex:
        msg = (
            f"The '{ex.resource_type}' to be created by this action already "
            "exists with different parameters than given to the action. This "
            "will have to be cleaned up manually."
        )
        hookenv.log(f'{msg} Exception: {ex}')
        return hookenv.action_fail(
            f'{msg} Check the unit logs for more details.')
    except exceptions.APIException as ex:
        hookenv.log(
            "Encountered exception while creating the Trove management "
            f"network. Exception: {ex}")
        return hookenv.action_fail(
            'Neutron API may not be available yet, rerun action when it is. '
            'Check the unit logs for more details.')


def _validate_create_mgmt_net_action_args(action_args):
    if not utils.is_cidr(action_args['cidr']):
        return hookenv.action_fail(
            "'cidr' argument is invalid. Must be a proper CIDR.")

    dest_cidr = action_args.get('destination-cidr')
    nexthop = action_args.get('nexthop')
    # destination-cidr and nexthop are optional, but if they're given, both of
    # them need to be given.
    if any([dest_cidr, nexthop]) and not all([dest_cidr, nexthop]):
        return hookenv.action_fail(
            "Either both 'destination-cidr' and 'nexthop' arguments must be "
            "given, or neither.")

    if dest_cidr and not utils.is_cidr(dest_cidr):
        return hookenv.action_fail(
            "'destination-cidr' argument is invalid. Must be a proper CIDR.")

    if nexthop and not utils.is_ip(nexthop):
        return hookenv.action_fail(
            "'nexthop' argument is invalid. Must be an IP.")


def load_datastore_cfg_params_action(*args):
    """Runs trove-manage db_load_datastore_config_parameters on controller."""
    if not reactive.all_flags_set('identity-service.available',
                                  'shared-db.available',
                                  'amqp.available'):
        return hookenv.action_fail(
            'all required relations are not available, please defer action '
            'until deployment is complete.'
        )

    action_args = hookenv.action_get()

    # Download the config file from the URL and save it in /tmp.
    config_file_url = action_args["config-file"]
    resp = requests.get(config_file_url)
    config_file_path = os.path.join("/tmp", os.path.basename(config_file_url))
    with open(config_file_path, "wb") as f:
        f.write(resp.content)

    subprocess_args = [
        "trove-manage",
        "db_load_datastore_config_parameters",
        action_args["datastore"],
        action_args["datastore-version-name"],
        config_file_path,
    ]
    if action_args.get("version"):
        subprocess_args += ["--version", action_args["version"]]

    return subprocess.check_call(subprocess_args)


# Actions to function mapping, to allow for illegal python action names that
# can map to a python function.
ACTIONS = {
    "db-load-datastore-config-params": load_datastore_cfg_params_action,
    "create-management-network": create_mgmt_network_action,
}


def main(args):
    # Manually trigger any register atstart events to ensure all endpoints
    # are correctly setup, Bug #1916008.
    hookenv._run_atstart()
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return f"Action {action_name} undefined"
    else:
        try:
            action(args)
        except Exception as e:
            hookenv.action_fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
