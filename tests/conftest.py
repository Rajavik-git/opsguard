import pytest

from opsguard.guardrails import Guardrails
from opsguard.runtime import load_config, scenarios


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def all_scenarios(cfg):
    return scenarios(cfg)


@pytest.fixture
def guards(cfg):
    return Guardrails(cfg["paths"]["policy"])
