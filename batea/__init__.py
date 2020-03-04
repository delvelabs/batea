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

from .core.nmap_parser import NmapReportParser
from .core.csv_parser import CSVFileParser
from .core.report import NmapReport, Host, Port
from .core.output_manager import OutputManager, MatrixOutput, JsonOutput
from .core.pandas_util import PandasBatea
from .features import FeatureBase


from .features.basic_features import TotalPortCountFeature, OpenPortCountFeature, IpOctetFeature
from .features.basic_features import LowPortCountFeature, NamedServiceCountFeature, BannerCountFeature
from .features.basic_features import MaxBannerLengthFeature, WindowsOSFeature, LinuxOSFeature
from .features.basic_features import HttpServerCountFeature, DatabaseCountFeature, CommonWindowsDomainAdminFeature
from .features.basic_features import CommonWindowsDomainMemberFeature, PortEntropyFeature, HostnameLengthFeature
from .features.basic_features import HostnameEntropyFeature, TCPPortCountFeature


def build_report():
    report = NmapReport()
    report.add_feature(IpOctetFeature(0))
    report.add_feature(IpOctetFeature(1))
    report.add_feature(IpOctetFeature(2))
    report.add_feature(IpOctetFeature(3))
    report.add_feature(TotalPortCountFeature())
    report.add_feature(OpenPortCountFeature())
    report.add_feature(LowPortCountFeature())
    report.add_feature(TCPPortCountFeature())
    report.add_feature(NamedServiceCountFeature())
    report.add_feature(BannerCountFeature())
    report.add_feature(MaxBannerLengthFeature())
    report.add_feature(WindowsOSFeature())
    report.add_feature(LinuxOSFeature())
    report.add_feature(HttpServerCountFeature())
    report.add_feature(DatabaseCountFeature())
    report.add_feature(CommonWindowsDomainAdminFeature())
    report.add_feature(CommonWindowsDomainMemberFeature())
    report.add_feature(PortEntropyFeature())
    report.add_feature(HostnameLengthFeature())
    report.add_feature(HostnameEntropyFeature())

    return report
