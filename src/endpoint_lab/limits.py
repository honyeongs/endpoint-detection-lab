from dataclasses import dataclass


class InputError(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    file_bytes: int = 8 * 1024 * 1024
    events: int = 10000
    field_chars: int = 4096
    alerts: int = 500
    xml_depth: int = 16
    xml_nodes: int = 400000


DEFAULT = Limits()
