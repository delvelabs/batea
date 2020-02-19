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

from defusedxml import ElementTree
from ipaddress import ip_address
from .report import Host, Port


class NmapReportParser:

    def load_hosts(self, file):

        root = ElementTree.parse(file).getroot()
        for child in root.findall('host'):
            host = self._generate_host(child)

            yield host

    def _generate_host(self, subtree):
        return Host(ipv4=self._find_address(subtree),
                    hostname=self._find_hostname(subtree),
                    os_info=self._os_detection(subtree),
                    ports=self._find_ports(subtree))

    def _find_address(self, host):
        for addr in host.findall('address'):
            if addr.attrib["addrtype"] == "ipv4":
                return ip_address(addr.attrib["addr"])

    def _find_hostname(self, host):
        for hostname in host.findall('hostnames'):
            for name in hostname.findall('hostname'):
                if name.attrib["type"] == "PTR":
                    return name.attrib['name']

    def _find_ports(self, host):
        ports = []
        if host.find("ports") is not None:
            for port in host.find("ports").findall("port"):
                state = port.find("state")
                service = port.find('service')

                cpe = service.find('cpe') if service is not None else None
                port = Port(
                    port=int(port.attrib['portid']),
                    protocol=port.attrib['protocol'],
                    state=state.attrib['state'],
                    service=service.attrib['name'] if service is not None else None,
                    software=service.attrib['product'] if service is not None and 'product' in service.attrib else None,
                    version=service.attrib['version'] if service is not None and 'version' in service.attrib else None,
                    cpe=cpe.text if cpe is not None else None
                )

                ports.append(port)
        return ports

    def _os_detection(self, host):

        for os in host.findall('os'):
            for osmatch in os.findall('osmatch'):
                group = []

                for osclass in osmatch.findall('osclass'):
                    data = dict(self._format_os_info(osmatch, osclass))
                    if data:
                        group.append(data)
                if group:
                    return self._guess_os(group)

    def _format_os_info(self, osmatch, osclass):

        vendor = osclass.attrib["vendor"]
        family = osclass.attrib["osfamily"]

        yield "vendor", vendor
        if vendor == family:
            yield "family", vendor
        else:
            yield "family", "{} {}".format(vendor, family)

        yield "type", osclass.attrib["type"]
        yield "name", osmatch.attrib["name"]
        yield "accuracy", int(osclass.attrib["accuracy"])

    def _guess_os(self, candidates):
        ordered = sorted((c["accuracy"], -rank, c) for rank, c in enumerate(candidates))
        _, _, selected = ordered[-1]
        return selected
