# Juju Trove Charm


## Usage

Charm to deploy Trove in a Canonical OpenStack deployment.


## Environment setup

The Trove database instances are spawned with 2 NICs attached to them, one for
the tenant network, and one for the management network. The instances have
Trove guest agents running in them, which are supposed to connect to the Trove
control plane through AMQP using the management NIC. In a typical Juju
OpenStack deployment, they should be able to connect to the same RabbitMQ units
as the Trove control plane. In addition to that, the subnet allocated for Trove
instances need to sufficiently large enough to allow the maximum number of
instances and controllers likely to be deployed throughout the lifespan of the
cloud.

Below is a networking setup example:

```
     ┌────────────────────────────┐   ┌──────────────────────────┐
     │ Control Plane              │   │ Compute Node             │
     │ ┌────────────────────────┐ │   │ ┌──────────────────────┐ │
     │ │ LXD                    │ │   │ │ KVM                  │ │
     │ │ ┌──────────┐ ┌───────┐ │ │   │ │ ┌──────────────────┐ │ │
     │ │ │ RabbitMQ │ │ Trove │ │ │   │ │ │  Trove instance  │ │ │
     │ │ └──┬───────┘ └──┬────┘ │ │   │ │ ├────┐        ┌────┤ │ │
     │ │    │            │      │ │   │ │ │eth0│        │eth1│ │ │
     │ └────┼────────────┼──────┘ │   │ │ └──┬─┴────────┴──┬─┘ │ │
     │      ├────────────┘        │   │ └────┼─────────────┼───┘ │
     │ ┌────┴──┐ ┌──────┐ ┌─────┐ │   │   ┌──┴───┐    ┌────┴───┐ │
     │ │br-eth0│ │br-int├─┤br-ex│ │   │   │br-int├─┐  │br-trove│ │
     │ └──┬────┘ └──┬───┘ └───┬─┘ │   │   └──────┘ │  └─────┬──┘ │
     │ ┌──┴─┐    ┌──┴─┐    ┌──┴─┐ │   │ ┌────┐   ┌─┴──┐   ┌─┴──┐ │   ┌──────────┐
     │ │eth0│    │eth1│    │eth2│ │   │ │eth0│   │eth1│   │eth2│ │   │          │
     │ └──┬─┘    └──┬─┘    └──┬─┘ │   │ └──┬─┘   └──┬─┘   └──┬─┘ │   │  Router  │
     │    │         │         │   │   │    │        │        │   │   │          │
     └────┼─────────┼─────────┼───┘   └────┼────────┼────────┼───┘   └─┬──────┬─┘
          │         │         │            │        │        │         │      │
mgmt-net  │         │         │            │        │        │         │      │
──────────┴─────────┼─────────┼────────────┴────────┼────────┼─────────┴──────┼───
                    │         │                     │        │                │
tenant-net          │         │                     │        │                │
────────────────────┴─────────┼─────────────────────┴────────┼────────────────┼───
                              │                              │                │
public-net                    │                              │                │
──────────────────────────────┴──────────────────────────────┼────────────────┼───
                                                             │                │
trove-net                                                    │                │
─────────────────────────────────────────────────────────────┴────────────────┴───
```

- ``mgmt-net``: Network used for managing the Nodes and OpenStack services in
  the LXD units.
- ``tenant-net``: Network dedicated for guest VM networks.
- ``public-net``: Public network used for external access and floating IPs.
- ``trove-net``: Management network to be used by Trove, which is routed to
  the ``mgmt-net``. IPs in this subnet are managed by Neutron.

A Neutron flat network needs to be defined for ``trove-net`` with a subnet CIDR
that is being routed to the Juju management network (``mgmt-net``):

```bash
# Add a new flat network provider to neutron API charm, if not added already.
# They are separated by space.
# We're adding physnet2.
juju config neutron-api flat-network-providers="physnet1 physnet2"

# If Neutron OVS is being used:
juju config neutron-gateway bridge-mappings="physnet1:br-ex physnet2:br-trove" data-port="br-ex:eth2 br-trove:eth3"
juju config neutron-openvswitch bridge-mappings="physnet2:br-trove" data-port="br-trove:eth2"

# After the charm has been deployed, define the flat OpenStack network, and subnet
# with a route to the Management Network.
juju run-action trove/leader create-management-network physical-network=physnet2 \
  cidr=10.8.102.0/24 destination-cidr=10.8.11.0/24 nexthop=10.8.102.1

# The action above can be used to create VLAN networks as well. For more information
# about the action and its parameters, run:
juju show-action trove create-management-network

# The created resources can be retrieved by running:
openstack network list --tag charm-trove

# Alternatively, these resources can be created manually:
openstack network create --share --provider-network-type=flat \
  --provider-physical-network=physnet2 --description "Trove management network" trove-net

# We specify --gateway=none so it will not create 2 default routes
openstack subnet create --subnet-range=10.8.102.0/24 --gateway=none \
  --host-route destination=10.8.11.0/24,gateway=10.8.102.1 \
  --network trove-net trove-subnet
```

The Neutron network created above will be used to configure the Trove charm,
which will be covered in the [Configuration Options](#Configuration-Options)
section.

Trove can be configured with a management Neutron security group which will be
applied to the instances' management port (e.g.: allow SSH access). This can
be set through a Trove charm config option (see [Configuration Options](#Configuration-Options)
section).


## Charm building

In order to build the Trove charm, execute the following commands:

```bash
export CHARM_BASE="$HOME/work/charms"
export JUJU_REPOSITORY="$CHARM_BASE/builds"

mkdir -p $JUJU_REPOSITORY

# Install requirement for charm building.
sudo snap install --classic charm

# Clone the repository.
git clone https://github.com/cloudbase/trove-charm
cd trove-charm

# Build the charm.
charm build src
```

The charm should have been built in ``$JUJU_REPOSITORY/builds/trove``.


## Deploy the charm

```bash
# The charm can be deployed on a specific node, or an LXD container on a node
# by specifying the --to argument.
juju deploy $JUJU_REPOSITORY/builds/trove trove

# Add MySQL Router.
juju deploy mysql-router trove-mysql-router --channel 8.0/stable
juju relate trove-mysql-router mysql-innodb-cluster

# Add the necessary relations.
juju relate trove rabbitmq-server
juju relate trove keystone
juju relate trove trove-mysql-router

# Optionally add HA.
juju deploy --config cluster_count=3 hacluster hacluster-trove --channel 2.4/stable
juju relate trove:ha hacluster-trove:ha
```

To replace the current Trove charm with a newer revision and keeping the
existing relations and configuration, run the following command:

```bash
juju refresh --path $JUJU_REPOSITORY/builds/trove-charm trove
```

In order for the Trove charm to become Active, the ``management-network``
config option needs to be set with the network UUID created above. See the
[Configuration Options](#Configuration-Options) section.

For more details on the Management Network needed by Trove, check [here](https://docs.openstack.org/trove/latest/admin/run_trove_in_production.html#management-network).


## Using Trove

After the Trove charm has become Active, you can check that it can be accessed
by running:

```bash
# Load the OpenStack credentials.
. ~/admin-openrc.sh

# This requires python-troveclient to be installed.
openstack database instance list
```

There should be no errors while running the command above.

Next, we need to declare a Trove image and a datastore:

```bash
# Download an image built by the community.
# For more images and how to build them, see https://docs.openstack.org/trove/latest/admin/building_guest_images.html
wget https://tarballs.opendev.org/openstack/trove/images/trove-zed-guest-ubuntu-focal.qcow2
openstack image create trove-zed-guest-ubuntu-focal \
  --private \
  --disk-format qcow2 \
  --container-format bare \
  --tag trove --tag mysql \
  --file ./trove-zed-guest-ubuntu-focal.qcow2

# Declare a datastore.
openstack datastore version create 5.7.29 mysql mysql "" \
  --image-tags trove,mysql \
  --active --default

# Load the validation rules for the datastore.
CONF_FILE_URL="https://github.com/openstack/trove/blob/stable/zed/trove/templates/mysql/validation-rules.json"
juju run --wait trove/leader db-load-datastore-config-params \
  datastore=mysql datastore-version-name=5.7.29 config-file=$CONF_FILE_URL
```

Next, we can deploy database instances:

```bash
openstack database instance create mysql_instance_1 --flavor m1.large --size 3 \
  --nic net-id=$TENANT_NET_UUID --databases test --users userA:Passw0rd \
  --datastore mysql --datastore-version 5.7.29 --is-public \
  --allowed-cidr $TENANT_NET_CIDR

# Check that the instances become ACTIVE.
openstack database instance list
```


## Configuration Options

The Trove charm needs the ``management-networks`` config option in order to
become active. It needs to be set to the Neutron network created in the
[Environment setup](#Environment-setup) section:

```bash
juju config trove management-networks=$TROVE_NET_UID
```

A management Neutron security group can be created and assigned to the
management ports of the Trove instances by setting the ``management-security-groups``
config option:

```bash
openstack security group create trove-sg --description "Trove Security Group" --tag "trove-charm"
openstack security group rule create trove-sg --dst-port 22 --protocol tcp --ingress --ethertype ipv4
juju config trove management-security-groups=$TROVE_SG_UID
```

The security group above adds a SSH ingress rule. The Trove instances will need
an SSH keypair:

```bash
# Get the Trove user ID.
openstack user list --project services

# Create the keypair for the Trove user ID.
openstack keypair create --user $TROVE_USER_ID --public-key ~/.ssh/id_rsa.pub trove-keypair

# Configure Trove to spawn instances with the SSH keypair.
juju config trove nova-keypair=trove-keypair
```


## Restrictions

