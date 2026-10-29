import os
import sys
import tempfile

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(HERE))
_tmp = tempfile.mkdtemp()
os.environ["NETMON_DB"] = os.path.join(_tmp, "test.db")
# synthetic fixture (documentation/private addresses only); never the deployment's own config.yaml
os.environ["NETMON_CONFIG"] = os.path.join(HERE, "fixtures", "config.yaml")
os.environ["NETMON_DETECTOR"] = "0"


@pytest.fixture
def cfg():
    from netmon.core import load_config
    return load_config(os.environ["NETMON_CONFIG"])


@pytest.fixture
def conn(tmp_path):
    from netmon.core import db_connect
    return db_connect(str(tmp_path / "t.db"))
