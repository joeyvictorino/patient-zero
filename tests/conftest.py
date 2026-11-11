import os
import sys

import pytest


from patient_zero.demo.leaky_clinic import make_server  # noqa: E402


@pytest.fixture
def vulnerable_server():
    server = make_server(vulnerable=True)
    yield server
    server.shutdown()


@pytest.fixture
def fixed_server():
    server = make_server(vulnerable=False)
    yield server
    server.shutdown()
