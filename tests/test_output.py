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

from batea import OutputManager, NmapReport, Host, Port, FeatureBase
from ipaddress import ip_address


def test_general_add_data_create_key_if_key_not_in_data():
    output_manager = OutputManager()
    output_manager._add_data("new_key", "value")

    assert "new_key" in output_manager.data


def test_general_add_data_put_data_in_list():
    output_manager = OutputManager()
    output_manager._add_data("key", "value")

    assert output_manager.data["key"] == ["value"]


def test_general_add_data_extends_existing_list_if_data_is_list():
    output_manager = OutputManager()
    output_manager._add_data('key', "value0")
    output_manager._add_data('key', ["value1", "value2"])

    assert output_manager.data["key"] == ["value0", "value1", "value2"]


def test_general_log_message_append_message_to_existing_log():
    output_manager = OutputManager()
    output_manager.log_message("message0")
    output_manager.log_message("message1")

    assert output_manager.data["general_log"] == ["message0", "message1"]


def test_add_report():
    output_manager = OutputManager()

    report = NmapReport()
    report.add_hosts([Host(), Host()])
    report.add_feature(FeatureBase('feature1'))

    output_manager.add_report_info(report)

    assert output_manager.data['report_info'][0]['number_of_hosts'] == 1
    assert output_manager.data['report_info'][0]['features'] == ['feature1']


def test_add_host_info():
    output_manager = OutputManager(verbosity=2)

    host = Host(ipv4=ip_address('8.8.8.8'), hostname='the.hive')
    host.add_port(Port(88))

    output_manager.add_host_info(rank=1, score=0, host=host, features={'feature1', 123})

    assert output_manager.data['host_info'][0]['host'] == "8.8.8.8"
    assert output_manager.data['host_info'][0]['hostname'] == "the.hive"
    assert output_manager.data['host_info'][0]['features'] == {'feature1', 123}

    assert len(output_manager.data['host_info'][0]['ports']) == 1
    assert output_manager.data['host_info'][0]['ports'][0]['port'] == 88
