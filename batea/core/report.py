# batea: context-driven asset ranking using anomaly detection
# Copyright (C) 2019-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import numpy as np


class NmapReport:

    def __init__(self):
        self.hosts = []
        self.matrix_representation = None
        self._features = []

    def add_feature(self, feature):
        self._features.append(feature)

    def add_hosts(self, *hosts):
        self.hosts.extend(hosts)

    def get_features(self):
        for feature in self._features:
            yield feature

    def get_feature_names(self):
        return [feature.name for feature in self._features]

    def generate_matrix_representation(self):
        rep = np.empty(shape=(len(self.hosts), len(self._features)))
        for col, feature in enumerate(self._features):
            rep[:, col] = feature.transform(self.hosts)
        return rep


class Host:

    def __init__(self, ipv4=None, hostname=None, os_info=None, ports=None):
        self.ipv4 = ipv4
        self.hostname = hostname
        self.os_info = os_info
        self.ports = ports or []

    def add_port(self, port):
        self.ports.append(port)


class Port:

    def __init__(self, port, protocol=None, state=None, service=None,
                 software=None, version=None, cpe=None, scripts=None, **kwargs):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.software = software
        self.version = version
        self.cpe = cpe
        self.scripts = scripts

    def get_banner_length(self):
        return len(self.software) if self.software else 0
