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

from .feature import FeatureBase
from collections import Counter
import numpy as np


class IpOctetFeature(FeatureBase):

    def __init__(self, octet):
        self.octet = octet
        super().__init__(name=f"ip_octet_{octet}")

    def _transform(self, hosts):
        """Return the specific IP octet to act as an address range context indicator.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer, representation of the octet at the position defined by the class argument.
        """
        f = lambda x: int(x.ipv4.exploded.split('.')[self.octet])
        return f


class TotalPortCountFeature(FeatureBase):

    def __init__(self):
        super().__init__(name="port_count")

    def _transform(self, hosts):
        """Returns the total port count fot the device, regardless of state and protocol.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer, counts the number of ports.
        """
        f = lambda x: len(x.ports)
        return f


class OpenPortCountFeature(FeatureBase):

    def __init__(self):
        super().__init__(name="open_port_count")

    def _transform(self, hosts):
        """Returns the total number of open ports, regardless of protocol.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer, sums the number of ports if the state is open.
        """
        f = lambda x: len([port for port in x.ports if port.state == 'open'])
        return f


class LowPortCountFeature(FeatureBase):

    def __init__(self):
        super().__init__(name="low_port_count")

    def _transform(self, hosts):
        """Returns the number of open ports whose port number is below 10000.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer, sums the number of open ports below 10000.
        """
        f = lambda x: len([port for port in x.ports if port.state == 'open' and port.port <= 9999])
        return f


class TCPPortCountFeature(FeatureBase):

    def __init__(self):
        super().__init__(name="tcp_port_count")

    def _transform(self, hosts):
        """Returns the number of open ports that uses the TCP protocol.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer, sums the number of open tcp ports.
        """
        f = lambda x: len([port for port in x.ports if port.state == 'open' and port.protocol == 'tcp'])
        return f


class NamedServiceCountFeature(FeatureBase):

    def __init__(self):
        super().__init__(name="named_service_count")

    def _transform(self, hosts):
        """Returns the number of ports for which the service is recognized (using IANA service names registry).

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer sums the number of ports that have been recognized by nmap.
        """
        f = lambda x: len([port for port in x.ports if port.service is not None and port.service != "unknown"])
        return f


class BannerCountFeature(FeatureBase):

    def __init__(self):
        super().__init__(name="software_banner_count")

    def _transform(self, hosts):
        """Returns the number of ports for which a specific software banner has been returned.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integern, sums the number of ports if any software info has been found.
        """
        f = lambda x: len([port for port in x.ports if port.software])
        return f


class MaxBannerLengthFeature(FeatureBase):

    def __init__(self):
        super().__init__(name="max_banner_length")

    def _transform(self, hosts):
        """Returns the lenght of the largest banner found on the asset, as it could indicate a misconfigured
        service with unnecessary verbose output.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer, max of all banner lenghts.
        """
        f = lambda x: max([port.get_banner_length() for port in x.ports], default=0)
        return f


class WindowsOSFeature(FeatureBase):
    def __init__(self):
        super().__init__(name="is_windows")

    def _transform(self, hosts):
        """Returns a binary value if the machine's os fingerprint returned Windows.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              1 if windows, 0 otherwise.
        """
        f = lambda x: 1 if x.os_info is not None and 'windows' in x.os_info.get('name', '').lower() else 0
        return f


class LinuxOSFeature(FeatureBase):
    def __init__(self):
        super().__init__(name="is_linux")

    def _transform(self, hosts):
        """Returns a binary value if the machine's os fingerprint returned Linux.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              1 if linux, 0 otherwise.
        """
        f = lambda x: 1 if x.os_info is not None and 'linux' in x.os_info.get('name', '').lower() else 0
        return f


class HttpServerCountFeature(FeatureBase):
    def __init__(self):
        super().__init__(name="http_server_count")

    def _transform(self, hosts):
        """Returns the number of http servers found on the asset, as an indicator of the devices use and accessibility.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer sum of all ports with an http service,
        """
        f = lambda x: len([port for port in x.ports if port.service is not None and 'http' in port.service])
        return f


class DatabaseCountFeature(FeatureBase):
    def __init__(self):
        super().__init__(name="database_count")

    def _transform(self, hosts):
        """Returns the number of database services, as an indicator of the asset's importance.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer sum of all ports which return a port number or service name relating to a database service.
        """
        db_ports = [1433, 1434, 3306, 5432, 1521, 1830, 9200, 9300, 7000, 7001, 9042, 6379, 5984]
        db_services = ['sql', 'mysql', 'mssql', 'oracle', 'elasticsearch', 'cassandra', 'mongo', 'redis', 'couchdb']

        f = lambda x: len([port for port in x.ports if port.port in db_ports or port.service in db_services])
        return f


class CommonWindowsDomainAdminFeature(FeatureBase):
    def __init__(self):
        super().__init__(name="windows_domain_admin_count")

    def _transform(self, hosts):
        """Returns the number of windows specific domain admin services.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer, sums ports who are member of the predefined list.
        """
        admin_ports = [53, 88, 389, 636, 445]
        f = lambda x: len([port for port in x.ports if port.port in admin_ports])
        return f


class CommonWindowsDomainMemberFeature(FeatureBase):
    def __init__(self):
        super().__init__(name="windows_domain_member_count")

    def _transform(self, hosts):
        """Returns the number of windows specific domain member services.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Integer, sums ports who are member of the predefined list.
        """
        member_ports = [25, 135, 137, 139, 3268, 3269]
        f = lambda x: len([port for port in x.ports if port.port in member_ports])
        return f


class PortEntropyFeature(FeatureBase):
    def __init__(self):
        super().__init__(name="port_entropy")

    def _transform(self, hosts):
        """Returns the entropy of port numbers as a measure of regularity of the combination of ports.
        It is believed that an asset with highly irregular port pattern might be an indicator of importance or
        misconfiguration.

          Parameters
          ----------
          hosts : list
              The list of all hosts.

          Returns
          -------
          f : lambda function
              Float, the sum of the expected surprise of the port number combination.
        """

        port_list = [port.port for host in hosts for port in host.ports]
        frequency = Counter(port_list)
        total = len(port_list)
        f = lambda x: -sum([(frequency[p.port]/total)*np.log2(frequency[p.port]/total) for p in x.ports])
        return f


class HostnameLengthFeature(FeatureBase):
        def __init__(self):
            super().__init__(name="hostname_length")

        def _transform(self, hosts):
            """Returns the lenght of the hostname.

              Parameters
              ----------
              hosts : list
                  The list of all hosts

              Returns
              -------
              f : lambda function
                  Integer, the nubmer of characters in the hostname, defaulting to 0.
            """
            f = lambda x: len(x.hostname) if x.hostname is not None else 0
            return f


class HostnameEntropyFeature(FeatureBase):
    def __init__(self):
        super().__init__(name="hostname_entropy")

    def _transform(self, hosts):
        """Returns the character-level entropy of hostname as a measure of regularity in the naming schemes.
        It is believed that an asset with highly irregular naming pattern might be an indicator of importance or
        misconfiguration.

          Parameters
          ----------
          hosts : list
              The list of all hosts

          Returns
          -------
          f : lambda function
              Float, the expected surprise of characters in the hostname.
        """
        char_list = []
        hostname_chars = [list(host.hostname) if host.hostname is not None else '' for host in hosts]
        for hostname in hostname_chars:
            char_list.extend(hostname)
        frequency = Counter(char_list)
        total = len(char_list)

        f = lambda x: -sum([(frequency[c]/total)*np.log2(frequency[c]/total) for c in x.hostname or ''])
        return f
