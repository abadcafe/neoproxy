"""Typed YAML configuration serialization for process fixtures."""

import json

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type ConfigDict = dict[str, JsonValue]
type StringMap = dict[str, str]


def dict_to_yaml(config: ConfigDict) -> str:
    """Convert a config dict to YAML string manually.

    Avoids yaml.dump() formatting issues with the Rust serde_yaml parser.
    All top-level keys are rendered generically via _yaml_value, which handles
    dicts, lists, lists-of-dicts, strings, booleans, and nulls. This ensures
    any new config key (e.g. tls, plugins) is rendered correctly without
    silent data loss.
    """
    lines: list[str] = []

    for key, value in config.items():
        lines.extend(_yaml_value(key, value, indent=0))

    return "\n".join(lines) + "\n"


def _yaml_dict(
    d: dict[str, JsonValue], indent: int, key: str | None = None
) -> list[str]:
    """Render a dict as YAML key-value lines with proper indentation.

    Args:
        d: The dictionary to render.
        indent: The indentation level (number of spaces) for the first key.
        key: Optional parent key name. If provided, the key is rendered first.

    Returns:
        List of YAML lines.
    """
    prefix = " " * indent
    lines: list[str] = []
    if key is not None:
        lines.append(f"{prefix}{key}:")
        indent += 2
        prefix = " " * indent

    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            sub_lines = _yaml_dict(v, indent=indent + 2)
            lines.extend(sub_lines)
        elif isinstance(v, list):
            # Check if it's a list of dicts (sequence of mappings)
            if v and isinstance(v[0], dict):
                lines.append(f"{prefix}{k}:")
                for item in v:
                    assert isinstance(item, dict)
                    lines.append(f"{prefix}  -")
                    for ik, iv in item.items():
                        lines.extend(_yaml_value(ik, iv, indent=indent + 4))
            else:
                lines.append(f"{prefix}{k}: {json.dumps(v)}")
        elif isinstance(v, str):
            lines.append(f'{prefix}{k}: "{v}"')
        elif isinstance(v, bool):
            lines.append(f"{prefix}{k}: {'true' if v else 'false'}")
        elif v is None:
            lines.append(f"{prefix}{k}: null")
        else:
            lines.append(f"{prefix}{k}: {v}")
    return lines


def _yaml_value(key: str, value: JsonValue, indent: int = 0) -> list[str]:
    """Render a single YAML key-value pair, handling dicts, lists, and scalars.

    Used for dynamic keys that don't have special rendering rules.

    Args:
        key: The YAML key.
        value: The value to render.
        indent: The indentation level (number of spaces).

    Returns:
        List of YAML lines.
    """
    prefix = " " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        lines.append(f"{prefix}{key}:")
        lines.extend(_yaml_dict(value, indent=indent + 2))
    elif isinstance(value, list):
        # Check if it's a list of dicts (sequence of mappings)
        if value and isinstance(value[0], dict):
            lines.append(f"{prefix}{key}:")
            for item in value:
                assert isinstance(item, dict)
                lines.append(f"{prefix}  -")
                for ik, iv in item.items():
                    lines.extend(_yaml_value(ik, iv, indent=indent + 4))
        else:
            lines.append(f"{prefix}{key}: {json.dumps(value)}")
    elif isinstance(value, str):
        lines.append(f'{prefix}{key}: "{value}"')
    elif isinstance(value, bool):
        lines.append(f"{prefix}{key}: {'true' if value else 'false'}")
    elif value is None:
        lines.append(f"{prefix}{key}: null")
    else:
        lines.append(f"{prefix}{key}: {value}")
    return lines
