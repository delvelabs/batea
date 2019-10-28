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

from batea import NmapReport, Host, Port
from ipaddress import ip_address
from batea.features.basic_features import TotalPortCountFeature, OpenPortCountFeature, IpOctetFeature
from batea.features.basic_features import LowPortCountFeature, NamedServiceCountFeature, BannerCountFeature
from batea.features.basic_features import MaxBannerLengthFeature, WindowsOSFeature, LinuxOSFeature
from batea.features.basic_features import HttpServerCountFeature, DatabaseCountFeature, CommonWindowsDomainAdminFeature
from batea.features.basic_features import CommonWindowsDomainMemberFeature, PortEntropyFeature, HostnameLengthFeature
from batea.features.basic_features import HostnameEntropyFeature


def test_total_port_count():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=22, protocol='tcp', state='open'),
                                                           Port(port=80, protocol='tcp', state='open')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=443, protocol='tcp', state='open'),
                                                           Port(port=22, protocol='tcp', state='closed')])]

    report.add_feature(TotalPortCountFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 1)
    assert array[0, 0] == 2
    assert array[1, 0] == 2


def test_open_port_count():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=22, protocol='tcp', state='open'),
                                                           Port(port=21, protocol='tcp', state='open')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=443, protocol='tcp', state='open'),
                                                           Port(port=8080, protocol='tcp', state='closed')])]

    report.add_feature(OpenPortCountFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 1)
    assert array[0, 0] == 2
    assert array[1, 0] == 1


def test_ip_octets():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1')),
                    Host(ip_address('192.168.1.2'))]

    report.add_feature(IpOctetFeature(0))
    report.add_feature(IpOctetFeature(1))
    report.add_feature(IpOctetFeature(2))
    report.add_feature(IpOctetFeature(3))

    array = report.generate_matrix_representation()

    assert array.shape == (2, 4)

    assert array[0, 0] == 192
    assert array[0, 1] == 168
    assert array[0, 2] == 1
    assert array[0, 3] == 1

    assert array[1, 0] == 192
    assert array[1, 1] == 168
    assert array[1, 2] == 1
    assert array[1, 3] == 2


def test_low_port_count():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=22, protocol='tcp', state='open'),
                                                           Port(port=80, protocol='tcp', state='open')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=35000, protocol='tcp', state='open'),
                                                           Port(port=22, protocol='tcp', state='closed')])]

    report.add_feature(LowPortCountFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 1)
    assert array[0, 0] == 2
    assert array[1, 0] == 0


def test_named_port_count():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=22, protocol='tcp', service='ssh'),
                                                           Port(port=80, protocol='tcp', service='http')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=22, protocol='tcp', service='unknown'),
                                                           Port(port=222, protocol='tcp', service='ssh')])]

    report.add_feature(NamedServiceCountFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 1)
    assert array[0, 0] == 2
    assert array[1, 0] == 1


def test_banner_count():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=22, name='ssh', software='OpenSSH'),
                                                           Port(port=80, state='open')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=8080, service='http'),
                                                           Port(port=80, service='http')])]

    report.add_feature(BannerCountFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 1)
    assert array[0, 0] == 1
    assert array[1, 0] == 0


def test_banner_length():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=22, software='OpenSSH Version 1'),
                                                           Port(port=80, software='VMware Authentication Daemon')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=22, software=None),
                                                           Port(port=35000, state='open', service='http')])]

    report.add_feature(MaxBannerLengthFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 1)
    assert array[0, 0] == len('VMware Authentication Daemon')
    assert array[1, 0] == 0


def test_http_servers_count():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=80, service='http'),
                                                           Port(port=8080, service='http')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=443, service='https'),
                                                           Port(port=22, service='ssh')])]

    report.add_feature(HttpServerCountFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 1)
    assert array[0, 0] == 2
    assert array[1, 0] == 1


def test_db_count():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=3306, service='mysql'),
                                                           Port(port=3307, service='sql')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=9999, service='redis'),
                                                           Port(port=22, service='ssh')])]

    report.add_feature(DatabaseCountFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 1)
    assert array[0, 0] == 2
    assert array[1, 0] == 1


def test_windows_domain_count():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=53, service='domain'),
                                                           Port(port=88, service='kerberos'),
                                                           Port(port=135, service='msrpc'),
                                                           Port(port=139, service='netbios-ssn')]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=135, service='msrpc'),
                                                           Port(port=139, service='netbios-ssn')])]

    report.add_feature(CommonWindowsDomainAdminFeature())
    report.add_feature(CommonWindowsDomainMemberFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 2)
    assert array[0, 0] == 2
    assert array[0, 1] == 2
    assert array[1, 0] == 0
    assert array[1, 1] == 2


def test_os_binary_features():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), os_info={'vendor': 'Linux',
                                                             'name': 'Linux 3.16 - 4.6',
                                                             'type': 'general purpose'}),
                    Host(ip_address('192.168.1.2'), os_info={'vendor': 'Microsoft',
                                                             'name': 'Windows xp',
                                                             'type': 'general purpose'})]

    report.add_feature(WindowsOSFeature())
    report.add_feature(LinuxOSFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (2, 2)
    assert array[0, 0] == 0
    assert array[0, 1] == 1
    assert array[1, 0] == 1
    assert array[1, 1] == 0


def test_port_entropy():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[Port(port=53), Port(port=88), Port(port=135)]),
                    Host(ip_address('192.168.1.2'), ports=[Port(port=53), Port(port=88), Port(port=135)]),
                    Host(ip_address('192.168.1.3'), ports=[Port(port=53), Port(port=88), Port(port=135)]),
                    Host(ip_address('192.168.1.4'), ports=[Port(port=53), Port(port=88), Port(port=135)]),
                    Host(ip_address('192.168.1.6'), ports=[Port(port=1), Port(port=2), Port(port=3)]),
                    ]

    report.add_feature(PortEntropyFeature())

    array = report.generate_matrix_representation()

    assert array.shape == (5, 1)
    assert array[1, 0] == array[0, 0]
    assert array[2, 0] == array[0, 0]
    assert array[3, 0] == array[0, 0]
    assert array[4, 0] < array[0, 0]


def test_hostname_length():
    report = NmapReport()
    report.hosts = [
        Host(ip_address('192.168.1.1'), hostname='delvesecurity.com', ports=[Port(port=53)]),
        Host(ip_address('192.168.1.2'), hostname='', ports=[Port(port=53)]),
        Host(ip_address('192.168.1.3'), hostname=None, ports=[Port(port=53)]),
    ]
    report.add_feature(HostnameLengthFeature())
    array = report.generate_matrix_representation()

    assert array.shape == (3, 1)
    assert array[0, 0] == len('delvesecurity.com')
    assert array[1, 0] == 0
    assert array[2, 0] == 0


def test_hostname_entropy():
    report = NmapReport()
    report.hosts = [
        Host(ip_address('192.168.1.1'), hostname='9ba3e58904.delvesecurity.com', ports=[Port(port=53)]),
        Host(ip_address('192.168.1.2'), hostname='subdomain1.delvesecurity.com', ports=[Port(port=53)]),
        Host(ip_address('192.168.1.3'), hostname='subdomain2.delvesecurity.com', ports=[Port(port=53)]),
        Host(ip_address('192.168.1.4'), hostname=None, ports=[Port(port=53)])
    ]
    report.add_feature(HostnameEntropyFeature())
    array = report.generate_matrix_representation()

    assert array.shape == (4, 1)
    assert array[0, 0] <= array[1, 0]
    assert array[1, 0] == array[2, 0]
    assert array[3, 0] == 0
