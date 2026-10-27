"""Assemble integration-test fixtures from public scenario interfaces.

This module only adapts pytest dependencies and scopes. Scenario modules
own configuration preparation, network/process setup and resource cleanup.
"""

from collections.abc import Iterator
from functools import partial
from pathlib import Path

import pytest

from tests.fixtures.certificates import (
    generate_client_cert,
    generate_test_certificates,
)
from tests.fixtures.configuration import StringMap
from tests.fixtures.http_scenario import ProxyWithConfig, running_proxy
from tests.fixtures.matrix_model import CertificateFiles
from tests.fixtures.proxy_process import ProcessFactory, managed_processes
from tests.fixtures.tcp_peer import TargetServerFactory, managed_target_servers


@pytest.fixture
def proxy_with_config(tmp_path: Path) -> ProxyWithConfig:
    return partial(running_proxy, tmp_path)


@pytest.fixture
def proxy_process() -> Iterator[ProcessFactory]:
    with managed_processes() as start:
        yield start


@pytest.fixture
def target_server() -> Iterator[TargetServerFactory]:
    with managed_target_servers() as start:
        yield start


@pytest.fixture(scope="session")
def shared_certs_dir(tmp_path_factory: pytest.TempPathFactory) -> str:
    return str(tmp_path_factory.mktemp("neoproxy_certs"))


@pytest.fixture(scope="session")
def shared_test_certs(shared_certs_dir: str) -> StringMap:
    cert, key, ca, ca_key = generate_test_certificates(shared_certs_dir)
    return {
        "cert_path": cert,
        "key_path": key,
        "ca_path": ca,
        "ca_key_path": ca_key,
    }


@pytest.fixture(scope="session")
def shared_client_cert(
    shared_certs_dir: str, shared_test_certs: StringMap
) -> StringMap:
    cert, key = generate_client_cert(
        shared_certs_dir,
        shared_test_certs["ca_path"],
        shared_test_certs["ca_key_path"],
    )
    return {"client_cert_path": cert, "client_key_path": key}


@pytest.fixture(scope="session")
def matrix_certificates(
    tmp_path_factory: pytest.TempPathFactory,
    shared_test_certs: StringMap,
    shared_client_cert: StringMap,
) -> "CertificateFiles":
    directory = tmp_path_factory.mktemp("matrix_alien_ca")
    _, _, ca, ca_key = generate_test_certificates(str(directory))
    alien_cert, alien_key = generate_client_cert(str(directory), ca, ca_key)
    return CertificateFiles(
        server_cert=shared_test_certs["cert_path"],
        server_key=shared_test_certs["key_path"],
        ca=shared_test_certs["ca_path"],
        client_cert=shared_client_cert["client_cert_path"],
        client_key=shared_client_cert["client_key_path"],
        alien_cert=alien_cert,
        alien_key=alien_key,
    )
