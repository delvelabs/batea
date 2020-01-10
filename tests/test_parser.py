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

from batea import NmapReportParser, CSVFileParser
from os.path import join, dirname

nmap_full_filename = join(dirname(__file__), "samples/single_full.xml")
nmap_base_filename = join(dirname(__file__), "samples/single_base.xml")
nmap_malformed_filename = join(dirname(__file__), "samples/single_with_nulls.xml")

csv_short_filename = join(dirname(__file__), 'samples/batea_simple_csv')
csv_long_filename = join(dirname(__file__), 'samples/batea_long_csv')
csv_null_filename = join(dirname(__file__), 'samples/batea_null_csv')


def test_nmap_parser_generates_list_of_hosts():
    parser = NmapReportParser()
    with open(nmap_full_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))

    assert len(hosts) == 2


def test_nmap_parser_extract_hosts_ip_add():
    parser = NmapReportParser()
    with open(nmap_full_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))


    assert hosts[0].ipv4.exploded == "192.168.1.1"
    assert hosts[1].ipv4.exploded == "192.168.1.2"


def test_nmap_parser_extract_hostname():
    parser = NmapReportParser()
    with open(nmap_full_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))

    assert hosts[0].hostname == "test1.organization.org"


def test_nmap_parser_extract_os_information():
    parser = NmapReportParser()
    with open(nmap_full_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))

    assert hosts[0].os_info['vendor'] == "Hackerbox"
    assert hosts[0].os_info['family'] == "Hackerbox Linux"
    assert hosts[0].os_info['type'] == "general purpose"
    assert hosts[0].os_info['name'] == 'Linux 3.16 - 4.6'
    assert hosts[0].os_info['accuracy'] == 100


def test_nmap_parser_extract_port_lists():
    parser = NmapReportParser()
    with open(nmap_full_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))
    ports = list(hosts[0].ports)

    assert ports[0].port == 80
    assert ports[0].protocol == "tcp"
    assert ports[0].state == "open"
    assert ports[0].service == 'http'


def test_nmap_parser_extract_cpe_when_available():
    parser = NmapReportParser()
    with open(nmap_full_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))
    ports = list(hosts[1].ports)

    assert ports[0].cpe == "cpe:/a:openbsd:openssh:7.3"
    assert ports[1].cpe is None


def test_nmap_parser_extract_software_when_available():
    parser = NmapReportParser()
    with open(nmap_full_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))
    ports = list(hosts[1].ports)

    assert ports[0].software == "OpenSSH"
    assert ports[0].version == "7.3"


def test_nmap_parser_extract_info_from_simple_report():
    parser = NmapReportParser()
    with open(nmap_base_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))

    host = hosts[0]
    ports = list(host.ports)

    assert len(ports) == 11
    assert ports[0].port == 22
    assert ports[0].software is None
    assert not host.os_info


def test_nmap_parser_doesnt_crash_if_port_number_is_null_or_zero():
    parser = NmapReportParser()
    with open(nmap_malformed_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))

    assert len(hosts) == 2
    assert len(hosts[0].ports) == 1
    assert len(hosts[1].ports) == 0


def test_csv_parser_generates_list_of_hosts():
    parser = CSVFileParser()
    with open(csv_short_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))

    assert len(hosts) == 2
    assert hosts[0].ipv4.exploded == '10.251.53.100'


def test_csv_parser_generates_list_of_ports_for_each_hosts():
    parser = CSVFileParser()
    with open(csv_long_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))

    assert len(hosts) == 3
    assert len(hosts[-1].ports) == 12
    assert hosts[-1].ports[0].port == 853
    assert hosts[-1].ports[0].service == 'unknown'


def test_csv_parser_doesnt_generates_list_of_ports_if_port_number_is_null_or_zero():
    parser = CSVFileParser()
    with open(csv_null_filename, 'r') as f:
        hosts = list(parser.load_hosts(f))

    assert len(hosts) == 2
    assert len(hosts[0].ports) == 1
    assert len(hosts[1].ports) == 0
