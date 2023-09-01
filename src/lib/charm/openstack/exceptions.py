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

from keystoneauth1 import exceptions as ks_exc
from neutronclient.common import exceptions as neutron_exc


NEUTRON_EXCS = (
    ks_exc.catalog.EndpointNotFound,
    ks_exc.connection.ConnectFailure,
    ks_exc.discovery.DiscoveryFailure,
    ks_exc.http.ServiceUnavailable,
    ks_exc.http.InternalServerError,
    neutron_exc.ServiceUnavailable,
    neutron_exc.BadRequest,
    neutron_exc.NeutronClientException,
)


class TroveCharmException(Exception):

    msg_fmt = 'An exception occured.'

    def __init__(self, msg=None, **kwargs):
        self.kwargs = kwargs

        if not msg:
            msg = self.msg_fmt % kwargs
        else:
            msg = str(msg)

        self.msg = msg
        super().__init__(msg)


class DuplicateResource(TroveCharmException):
    msg_fmt = "A duplicate '%(resource_type)s' has been found: %(data)s"

    def __init__(self, msg=None, resource_type=None, data=None):
        super().__init__(msg, resource_type=resource_type, data=data)
        self.resource_type = resource_type


class InvalidResource(TroveCharmException):
    msg_fmt = ("Invalid %(resource_type)s with id %(id)s found. "
               "Details: %(details)s")

    def __init__(self, msg=None, resource_type=None, id=None, details=None):
        super().__init__(msg, resource_type=resource_type, id=id,
                         details=details)
        self.resource_type = resource_type


class APIException(TroveCharmException):
    msg_fmt = ("An error occured while accessing the %(service)s "
               "%(resource_type)s API. Exception: %(exc)s")

    def __init__(self, msg=None, service=None, resource_type=None, exc=None):
        super().__init__(msg, service=service, resource_type=resource_type,
                         exc=exc)
