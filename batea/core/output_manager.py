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

import json
import numpy as np
from sys import stderr


class OutputManager:

    def __init__(self, verbosity=0, report=None):
        self.verbosity = verbosity
        self.data = {}
        self.report = report

    def log_message(self, message):
        self._add_data("general_log", message)

    def log_parse_error(self, e):
        stderr.write(e.__str__())
        stderr.write("\nUnable to parse file, invalid or corrupted filetype.\n")

    def log_empty_report(self):
        stderr.write("Empty report, can't predict. \nQuitting\n")

    def _format(self, data):
        raise NotImplementedError()

    def flush(self):
        self._format(self.data)

    def _add_data(self, key, value, container=None):
        if container is None:
            container = self.data
        if key not in container:
            container[key] = []
        if isinstance(value, list):
            container[key].extend(value)
        else:
            container[key].append(value)

    def add_report_info(self, report):
        self.report = report
        report_info = {
            'number_of_hosts': len(report.hosts),
            'features': report.get_feature_names()
                       }
        self._add_data('report_info', report_info)

    def add_host_info(self, rank, score, host, features):
        host_info = {
            'rank': rank,
            'host': host.ipv4.exploded,
            }
        if self.verbosity > 0:
            host_info['score'] = score
            host_info['hostname'] = host.hostname
            host_info['os'] = host.os_info
            host_info['features'] = features
        if self.verbosity == 2:
            host_info['ports'] = sorted([self._add_port_info(port) for port in host.ports], key=lambda p: p['port'])
        self._add_data('host_info', host_info)

    def _add_port_info(self, port):
        return port.__dict__

    def add_scores(self, scores):
        self.scores = scores


class JsonOutput(OutputManager):

    def _format(self, data):
        print(json.dumps(data, indent=4))


class MatrixOutput(OutputManager):

    def __init__(self, output_matrix):
        self.output_matrix = output_matrix
        super().__init__()

    def _format(self, data):
        matrix_rep = np.append(self.report.generate_matrix_representation(),
                               np.expand_dims(self.scores, axis=1),
                               axis=1)
        columns = self.report.get_feature_names() + ['anomaly_score']

        np.savetxt(self.output_matrix,
                   matrix_rep,
                   delimiter=',',
                   header=','.join(columns),
                   comments="")
