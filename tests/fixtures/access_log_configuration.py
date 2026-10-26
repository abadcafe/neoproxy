"""module: access_log_configuration.
Responsibility: enable selected access fields in process configurations.
Public operations: enable_access_log.
Data entities: none.
Tests: request-context and chain-diagnostic integration tests.
"""

from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import TypeAdapter

from tests.fixtures.configuration import ConfigDict, JsonValue, dict_to_yaml


def enable_access_log(config_path: str, fields: Sequence[str]) -> None:
    path = Path(config_path)
    config = TypeAdapter(ConfigDict).validate_python(yaml.safe_load(path.read_text()))
    plugins = TypeAdapter(ConfigDict).validate_python(config.get("plugins", {}))
    assert "access_log" not in plugins, (
        "fixture configuration already owns an access writer"
    )
    plugins["access_log"] = {
        "writers": [
            {"path_prefix": "logs/access", "format": "json", "flush_interval": "10ms"}
        ]
    }
    config["plugins"] = plugins
    services = TypeAdapter(list[ConfigDict]).validate_python(config["services"])
    for service in services:
        layers = TypeAdapter(list[ConfigDict]).validate_python(
            service.get("layers", [])
        )
        layer: ConfigDict = {
            "kind": "access_log.file",
            "args": {"writer": "logs/access", "context_fields": list(fields)},
        }
        combined: list[JsonValue] = [layer, *layers]
        service["layers"] = combined
    config["services"] = [service for service in services]
    _ = path.write_text(dict_to_yaml(config))
