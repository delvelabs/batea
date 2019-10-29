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

import numpy as np


class FeatureBase:
    """Feature base class"""

    def __init__(self, name=None):
        self.name = name

    def transform(self, hosts):
        """Generate a numpy column (type ndarray) to append to the base representation given a _transform function

          Parameters
          ----------
          hosts : list
              The list of all hosts

          Returns
          -------
          column : numpy ndarray
              Feature column indexed by host
         """
        f = self._transform(hosts)

        feature = map(f, hosts)
        column = np.array(list(feature), ndmin=2)
        return column

    def _transform(self, hosts):
        """specific transform method,should return a function that takes an host as input and return a numeric value

          Parameters
          ----------
          hosts : list
              The list of all hosts

          Returns
          -------
          f : lambda function
              transformation to apply to every host using a map
        """
        raise NotImplementedError
