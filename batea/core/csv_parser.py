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

import csv
from ipaddress import ip_address
from .report import Host, Port


ALLOWED_COLUMNS = [
    'ipv4',
    'hostname',
    'os_name',
    'port',
    'state',
    'protocol',
    'service',
    'software_banner',
    'version',
    'cpe',
    'other_info',
    ]


class CSVFileParser:

    def load_hosts(self, file):

        reader = csv.DictReader(file)

        current_host = None
        hosts = []
        for row in reader:
            if len(hosts) == 0 or hosts[-1].ipv4.exploded != row['ipv4']:
                hosts.append(Host(ipv4=ip_address(row.get('ipv4', None)),
                                  hostname=row.get('hostname', None),
                                  os_info={'name': row.get('os_name', None)}))

            if row.get('port', None) not in ['', None]:
                hosts[-1].ports.append(Port(
                    port=int(float(row.get('port', None))),
                    protocol=row.get('protocol', None),
                    state=row.get('state', None),
                    service=row.get('service', None),
                    software=row.get('software_banner', None),
                    version=row.get('version', None),
                    cpe=row.get('cpe', None)
                ))
        return hosts
