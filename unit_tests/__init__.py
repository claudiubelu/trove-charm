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

import sys
from unittest import mock

from oslotest import mock_fixture

# NOTE(claudiub): this needs to be called before any mock.patch calls are
# being done, and especially before any other test classes load. This fixes
# the mock.patch autospec issue:
# https://github.com/testing-cabal/mock/issues/396
mock_fixture.patch_mock_module()

sys.path.append('src')
sys.path.append('src/lib')

# Mock out charmhelpers so that we can test without it.
# also stops sideeffects from occuring.
import charms_openstack.test_mocks  # noqa
charms_openstack.test_mocks.mock_charmhelpers()

apt_pkg = mock.MagicMock()
charms = mock.MagicMock()
sys.modules['apt_pkg'] = apt_pkg
sys.modules['charms.layer'] = charms.layer
