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

from batea import NmapReport, Host
from batea.features import FeatureBase
from ipaddress import ip_address


def test_add_features():
    report = NmapReport()
    feature = FeatureBase(name='test_feature')
    report.add_feature(feature)

    report_features = list(report.get_features())

    assert len(report_features) == 1
    assert report_features[0].name == 'test_feature'


def test_generate_base_representation():
    report = NmapReport()
    report.hosts = [Host(ip_address('192.168.1.1'), ports=[{'port': 22, 'protocol': 'tcp', 'state': 'open'},
                                                           {'port': 80, 'protocol': 'tcp', 'state': 'open'}]),
                    Host(ip_address('192.168.1.2'), ports=[{'port': 443, 'protocol': 'tcp', 'state': 'open'},
                                                           {'port': 8080, 'protocol': 'tcp', 'state': 'closed'}])]

    array = report.generate_matrix_representation()

    assert array.shape == (2, 0)
