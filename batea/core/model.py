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

from sklearn.ensemble import IsolationForest
import numpy as np
import pickle


class BateaModel:

    def __init__(self, model=None, report_features=None, model_features=None):
        self.model = model
        self.report_features = report_features
        self.mode_features = model_features

    def build_model(self, outlier_ratio=0.1, n_estimators=100, max_samples='auto'):
        self.model = IsolationForest(contamination=outlier_ratio,
                                     n_estimators=n_estimators,
                                     max_samples=max_samples,
                                     behaviour='new')

    def load_model(self, model_file):
        self.model, self.model_features = pickle.load(model_file)
        assert self.model_features == self.report_features, \
            f"Model and data don't share matching features: {self.model_features} != {self.report_features}"

    def dump_model(self, dump_model):
        pickle.dump((self.model, self.report_features), dump_model)
