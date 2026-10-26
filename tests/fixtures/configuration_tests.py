"""Black-box contracts for lossless configuration serialization."""

from pydantic import TypeAdapter
from yaml import safe_load

from .configuration import ConfigDict, dict_to_yaml


def test_dict_to_yaml_round_trips_empty_maps_and_escaped_strings() -> None:
    config: ConfigDict = {
        "empty": {},
        "values": [None, {}, [], True, 'a"b\\c\nsecond line'],
        "key: with # syntax": {"http": {}, "password": 'secret"\nvalue'},
    }
    adapter = TypeAdapter(ConfigDict)
    assert adapter.validate_python(safe_load(dict_to_yaml(config))) == config


def test_dict_to_yaml_accepts_heterogeneous_sequences() -> None:
    config: ConfigDict = {"values": [{"http": {}}, "string", 42]}
    adapter = TypeAdapter(ConfigDict)
    assert adapter.validate_python(safe_load(dict_to_yaml(config))) == config
