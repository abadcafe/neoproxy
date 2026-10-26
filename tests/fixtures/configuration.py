"""Typed YAML configuration serialization for process fixtures."""

import yaml

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type ConfigDict = dict[str, JsonValue]
type StringMap = dict[str, str]


def dict_to_yaml(config: ConfigDict) -> str:
    """Serialize configuration values without changing their YAML types."""
    return yaml.safe_dump(config, sort_keys=False, allow_unicode=True)
