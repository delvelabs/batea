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


import click
from .core import NmapReportParser, NmapReport, CSVFileParser, JsonOutput, BateaModel, MatrixOutput
from defusedxml import ElementTree
from xml.etree.ElementTree import ParseError
from batea import build_report
import warnings
warnings.filterwarnings('ignore')


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option("-c", "--read-csv", type=click.File('r'), multiple=True)
@click.option("-x", "--read-xml", type=click.File('r'), multiple=True)
@click.option("-n", "--n-output", type=int, default=5)
@click.option("-A", "--output-all", is_flag=True)
@click.option("-L", "--load-model", type=click.File('rb'), default=None)
@click.option("-D", "--dump-model", type=click.File('wb'), default=None)
@click.option("-f", "--input-format", type=str, default='xml')
@click.option('-v', '--verbose', count=True)
@click.option('-oM', "--output-matrix", type=click.File('w'), default=None)
@click.argument("nmap_reports", type=click.File('r'), nargs=-1)
def main(*, nmap_reports, input_format, dump_model, load_model,
         output_all, read_csv, read_xml, n_output, verbose, output_matrix):
    """Context-driven asset ranking based using anomaly detection"""

    report = build_report()
    csv_parser = CSVFileParser()
    xml_parser = NmapReportParser()
    if output_matrix:
        output_manager = MatrixOutput(output_matrix)
    else:
        output_manager = JsonOutput(verbose)

    try:
        if input_format == 'xml':
            for file in nmap_reports:
                report.hosts.extend([host for host in xml_parser.load_hosts(file)])
        if input_format == 'csv':
            for file in nmap_reports:
                report.hosts.extend([host for host in csv_parser.load_hosts(file)])
        if read_csv:
            for file in read_csv:
                report.hosts.extend([host for host in csv_parser.load_hosts(file)])
        if read_xml:
            for file in read_xml:
                report.hosts.extend([host for host in xml_parser.load_hosts(file)])
    except (ParseError, UnicodeDecodeError, ElementTree.ParseError, ValueError) as e:
        output_manager.log_parse_error(e)
        raise SystemExit

    if len(report.hosts) == 0:
        output_manager.log_empty_report()
        raise SystemExit

    report_features = report.get_feature_names()
    output_manager.add_report_info(report)

    matrix_rep = report.generate_matrix_representation()

    batea = BateaModel(report_features=report_features)

    if load_model is not None:
        batea.load_model(load_model)

    else:
        batea.build_model()
        batea.model.fit(matrix_rep)

    scores = -batea.model.score_samples(matrix_rep)
    output_manager.add_scores(scores)

    if output_all:
        n_output = len(scores)
    n_output = min(n_output, len(scores))

    top_n = scores.argsort()[-n_output:][::-1]

    for i, j in enumerate(top_n):
        output_manager.add_host_info(
            rank=str(i+1),
            score=scores[j],
            host=report.hosts[j],
            features={name: value for name, value in zip(report_features, matrix_rep[j, :])}
        )
    output_manager.flush()

    if dump_model:
        batea.dump_model(dump_model)


if __name__ == "__main__":
    main()
