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

from .report import Host, Port, NmapReport
from .model import BateaModel
from ipaddress import ip_address
import numpy as np
import pandas as pd

from ..features.basic_features import TotalPortCountFeature, OpenPortCountFeature, IpOctetFeature
from ..features.basic_features import LowPortCountFeature, NamedServiceCountFeature, BannerCountFeature
from ..features.basic_features import MaxBannerLengthFeature, WindowsOSFeature, LinuxOSFeature
from ..features.basic_features import HttpServerCountFeature, DatabaseCountFeature, CommonWindowsDomainAdminFeature
from ..features.basic_features import CommonWindowsDomainMemberFeature, PortEntropyFeature, HostnameLengthFeature
from ..features.basic_features import HostnameEntropyFeature, TCPPortCountFeature


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


class PandasBatea:
    """Useful, self-contained utility class to use Batea inside a pandas data science pipeline or notebook."""
    def __init__(self):
        self.report = build_report()

    def transform(self, df):
        hosts = []
        for row in df.dropna(subset=['port']).iterrows():
            if len(hosts) == 0 or hosts[-1].ipv4.exploded != row[1]['ipv4']:
                hosts.append(Host(ipv4=ip_address(row[1].get('ipv4', None)),
                                  hostname=str(row[1].get('hostname', None)),
                                  os_info={'name': str(row[1].get('os_name', None))}))

            if row[1].get('port', None) not in ['', None]:
                hosts[-1].ports.append(Port(
                    port=int(float(row[1].get('port', 0))),
                    protocol=str(row[1].get('protocol', None)),
                    state=str(row[1].get('state', None)),
                    service=str(row[1].get('service', None)),
                    software=str(row[1].get('software_banner', None)),
                    version=str(row[1].get('version', None)),
                    cpe=str(row[1].get('cpe', None))
                ))
        self.report.hosts.extend(hosts)
        matrix_rep = self.report.generate_matrix_representation()
        report_features = self.report.get_feature_names()
        batea = BateaModel(report_features=report_features)
        batea.build_model()
        batea.model.fit(matrix_rep)
        scores = -batea.model.score_samples(matrix_rep)
        matrix_rep = np.append(self.report.generate_matrix_representation(),
                               np.expand_dims(scores, axis=1),
                               axis=1)
        columns = self.report.get_feature_names() + ['anomaly_score']

        return pd.DataFrame(matrix_rep, columns=columns)
