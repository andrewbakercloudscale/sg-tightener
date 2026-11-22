"""Every test runs against its own data directory, never the address lists or reads in ~/.sg-tightener: a list
downloaded there (by install.sh or a real run) must not change what a test sees."""

from __future__ import annotations

import pytest

import sg_ipintel


@pytest.fixture(autouse=True, scope="session")
def _own_data_dir(tmp_path_factory):
    old = sg_ipintel.DATA_DIR
    sg_ipintel.set_data_dir(tmp_path_factory.mktemp("sg-data"))
    yield
    sg_ipintel.set_data_dir(old)
