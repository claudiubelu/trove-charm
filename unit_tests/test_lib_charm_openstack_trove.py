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

from charm.openstack import trove


class TestTrove(unittest.TestCase):

    @mock.patch.object(trove.utils, 'get_trove_mgmt_sec_group')
    @mock.patch.object(trove.reactive, 'endpoint_from_flag')
    @mock.patch.object(trove.hookenv, 'config')
    def test_trove_security_group(self, mock_config, mock_endpoint_from_flag,
                                  mock_get_trove_sg):
        mock_config.return_value = mock.sentinel.set_config
        self.assertEquals(mock.sentinel.set_config,
                          trove.trove_security_group(mock.sentinel.cls))

        mock_config.return_value = None
        self.assertEquals(mock_get_trove_sg.return_value,
                          trove.trove_security_group(mock.sentinel.cls))
        mock_endpoint_from_flag.assert_called_once_with(
            'identity-service.available')
        mock_get_trove_sg.assert_called_once_with(
            mock_endpoint_from_flag.return_value)
