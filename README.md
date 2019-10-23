# Batea
*A batea is a large shallow pan of wood or iron traditionally used by gold prospecters for washing sand and gravel to recover gold nuggets.*

Batea is a context-driven network asset ranking framework based on the outlier detection family of machine learning algorithms. The goal of Batea is to allow security teams to automatically filter interesting network assets in large networks using nmap scan reports. It is easily extendable by adding features to the numerical representation of the network.

Batea works by constructing a numerical representation (numpy) from your nmap reports (XML) and then applying anomaly detection methods to uncover the gold nuggets buried in the mountain of your network information overload. 

The numerical representation is constructed using features drawn from the expertise of the security community. It has been conceived in order to be easily extendable. The features act as elements of intuition, and the unsupervised anomaly detection methods allow the context of the network asset to be used as the central building block of the ranking algorithm.

Ex:

```bash
$ sudo nmap -A 192.168.0.0/16 -oX output.xml
$ python -m batea -v output.xml
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
# simple use
$ python3 -m batea nmap_report.xml

# Output top 3
$ python3 -m batea -n 3 nmap_report.xml

# Output all assets
$ python3 -m batea -A nmap_report.xml

# training, output and dumping model for persistence
$ python3 -m batea -D mymodel.batea nmap_report.xml

# Using pretrained model
$ python3 -m batea -L mymodel.batea nmap_report.xml

# Using preformatted csv along with xml files
$ python3 -m batea -x nmap_report.xml -c portscan_data.csv

# Using wildcards (default xsml)
$ python3 -m batea ./nmap*.xml
$ python3 -m batea -f csv ./assets*.csv

# Adjust verbosity

$ python3 -m batea -vv nmap_report.xml
```

## How-To add a feature
Batea works by assigning numerical features to every host in the report (or series of reports).
Features are objects inherited from the `FeatureBase` class that instanciate a `_transform` method. This method takes the list of hosts as input and returns a lambda function that maps to a numpy column of numeric values, indexed by hosts (order is conserved). The column is then added to the matrix representation of the report.

Most feature transformations are implemented using a simple lambda function. Just make sure to give a default numeric value to every host for model compatibility.

Ex:
```python

class CustomInterestingPorts(FeatureBase):
    def __init__(self):
        super().__init__(name="some_custom_interesting_ports")

    def _transform(self, hosts):
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
