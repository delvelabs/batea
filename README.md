# Batea
*A batea is a large shallow pan of wood or iron traditionally used by gold prospecters for washing sand and gravel to recover gold nuggets.*

Batea is a context-driven network device ranking framework based on the anomaly detection family of machine learning algorithms. The goal of Batea is to allow security teams to __automatically filter interesting network assets__ in large networks using nmap scan reports. We call those *Gold Nuggets*.


Batea works by constructing a numerical representation (numpy) of all devices from your nmap reports (XML) and then applying anomaly detection methods to uncover the gold nuggets. It is easily extendable by adding specific features, or characteristics, to the numerical representation of the network elements.

The numerical representation of the network is constructed using features, which are inspired by the expertise of the security community. It has been conceived in order to be easily extendable. The features act as elements of intuition, and the unsupervised anomaly detection methods allow the context of the network asset to be used as the central building block of the ranking algorithm.

Models are the heart of Batea. Models are machine learning algorithms trained on the data and used to predict score on the same (and other) data. Batea also allow for model persistence. That is, you can re-use pretrained models and export models trained on large datasets for further use.

Ex:

```bash
$ sudo nmap -A 192.168.0.0/16 -oX output.xml
$ python -m batea -v output.xml
```
## Installation
```bash
$ git clone git@bitbucket.org:delvelabs/batea.git
$ cd batea
$ python3 setup.py sdist
$ pip3 install -r requirements.txt
$ pip3 install -e .
```

## Developers Installation

```bash
$ git clone git@bitbucket.org:delvelabs/batea.git
$ cd batea
$ python3 -m venv batea/
$ source batea/bin/activate
$ python3 setup.py sdist
$ pip3 install -r requirements-dev.txt
$ pip3 install -e .
$ pytest
```

## Example usage

```bash
# simple use (output top 5 gold nuggets with default format)
$ batea nmap_report.xml

# Output top 3
$ batea -n 3 nmap_report.xml

# Output all assets
$ batea -A nmap_report.xml

# Using multiple input files
$ batea -A nmap_report1.xml nmap_report2.xml

# Using wildcards (default xsl)
$ batea ./nmap*.xml
$ batea -f csv ./assets*.csv

# You can use batea on pretrained models and export trained models.
# Training, output and dumping model for persistence
$ batea -D mymodel.batea nmap_report.xml

# Using pretrained model
$ batea -L mymodel.batea nmap_report.xml

# Using preformatted csv along with xml files
$ batea -x nmap_report.xml -c portscan_data.csv



# Adjust verbosity

$ python3 -m batea -vv nmap_report.xml
```

## How-To add a feature
Batea works by assigning numerical features to every host in the report (or series of report).
Hosts are python objects derived from the nmap report. They consist of the following list of attributes: `[ipv4, hostname, os_info, ports]` where ports is a list of ports object. Each port has the following list of attributes : `[port, protocol, state, service, software, version, cpe, scripts]`, defaulting to `None`.

Features are objects inherited from the `FeatureBase` class that instantiate a `_transform` method. This method always take the list of all hosts as input and return a lambda function that maps each host to a numpy column of numeric values (host order is conserved). The column is then appended to the matrix representation of the report. Features have to output correct numerical values (floats or integers), nothing else.

Most feature transformations are implemented using a simple lambda function. Just make sure to default a numeric value to every host for model compatibility.

Ex:
```python

class CustomInterestingPorts(FeatureBase):
    def __init__(self):
        super().__init__(name="some_custom_interesting_ports")

    def _transform(self, hosts):
      """This method takes a list of host and return a function that counts the number
      of host ports member from a predefined list of "interesting" ports, defaulting to 0.

      Parameters
      ----------
      hosts : list
          The list of all hosts

      Returns
      -------
      f : lambda function
          Counts the number of ports member of the defined list.
      """
        member_ports = [21, 22, 25, 8080, 8081, 1234]
        f = lambda host: len([port for port in host.ports if port.port in member_ports])
        return f
```

You can then add the feature to the report by using the `NmapReport.add_feature` method in `batea/__init__.py`

```python
from .features.basic_features import CustomInterestingPorts

def build_report():
    report = NmapReport()
    #[...]
    report.add_feature(CustomInterestingPorts())

    return report
```

## Using precomputed tabular data (CSV)

It is possible to use preprocessed data to train the model or for prediction.
The data has to be indexed by `(ipv4, port)` with one unique combination per row. The type of data should be close to what you expect from the XML version of an nmap report.
A column has to use one of the following names, but you don't have to use all of them. The parser defaults to null values if a column is absent.
```python
  'ipv4',
  'hostname',
  'os_name',
  'port',
  'state',
  'protocol',
  'service',
  'software_banner',
  'version',
  'cpe',
  'other_info'
```
Example:
```
ipv4,hostname,os_name,port,state,protocol,service,software_banner
10.251.53.100,internal.delvesecurity.com,Linux,110,open,tcp,rpcbind,"program version   port/proto  service100000  2,3,4        111/tcp  rpcbind100000  2,3,4    "
10.251.53.100,internal.delvesecurity.com,Linux,111,open,tcp,rpcbind,
10.251.53.188,serious.delvesecurity.com,Linux,6000,open,tcp,X11,"X11Probe: CentOS"
```
