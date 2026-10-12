import hashlib
import ipaddress
import json
import ntpath
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .limits import DEFAULT, InputError, Limits

SUPPORTED_IDS = {1, 3, 5, 11}
ZERO_GUID = str(uuid.UUID(int=0))


def windows_path(value: str) -> str:
    return ntpath.normpath(value.replace("/", "\\")).casefold() if value else ""


def executable(value: str) -> str:
    return ntpath.basename(windows_path(value))


def writable_path(value: str) -> bool:
    path = windows_path(value)
    return any(part in path for part in ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\"))


def parse_time(value: str) -> datetime:
    try:
        if len(value.strip()) < 19 or value.strip()[10] not in {"T", "t", " "}:
            raise ValueError
        timestamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise InputError("Invalid UTC timestamp.") from None


def guid(value: str, *, optional=False) -> str:
    if not value and optional:
        return ""
    try:
        result = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise InputError("Invalid ProcessGuid or ParentProcessGuid.") from None
    if result == ZERO_GUID:
        if optional:
            return ""
        raise InputError("ProcessGuid must not be the zero GUID.")
    return result


@dataclass(frozen=True)
class Event:
    event_id: int
    timestamp: str
    host: str
    process_guid: str
    image: str
    record_id: int = 0
    pid: int = 0
    parent_process_guid: str = ""
    parent_image: str = ""
    command_line: str = ""
    user: str = ""
    target_filename: str = ""
    destination_ip: str = ""
    destination_port: int = 0
    initiated: bool | None = None

    @property
    def time(self) -> datetime:
        return parse_time(self.timestamp)

    @property
    def process_key(self) -> str:
        return self.host.casefold() + "|" + self.process_guid

    @property
    def key(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:24]

    def public(self) -> dict:
        return dict(asdict(self), key=self.key, process_key=self.process_key)


def normalize(raw: dict, limits: Limits = DEFAULT) -> Event:
    if not isinstance(raw, dict):
        raise InputError("Each event must be an object.")
    unknown = set(raw) - set(Event.__dataclass_fields__)
    if unknown:
        raise InputError("Unknown event fields; use the documented normalized JSON schema.")
    values = {}
    for name in Event.__dataclass_fields__:
        if name in {"event_id", "record_id", "pid", "destination_port", "initiated"}:
            continue
        value = raw.get(name, "")
        if not isinstance(value, str) or len(value) > limits.field_chars:
            raise InputError("Event text field exceeds limits or is not a string.")
        values[name] = value
    for name in ("event_id", "record_id", "pid", "destination_port"):
        value = raw.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
            raise InputError("Event identifiers and ports must be nonnegative integers.")
        values[name] = value
    if values["destination_port"] > 65535:
        raise InputError("Destination port exceeds 65535.")
    if values["event_id"] not in SUPPORTED_IDS:
        raise InputError("Supported event IDs are 1, 3, 5 and 11.")
    if not values["host"].strip() or len(values["host"]) > 255 or not values["image"].strip():
        raise InputError("Host and Image are required.")
    values["host"] = values["host"].strip().casefold()
    values["timestamp"] = parse_time(values["timestamp"]).isoformat(timespec="microseconds").replace("+00:00", "Z")
    values["process_guid"] = guid(values["process_guid"])
    values["parent_process_guid"] = guid(values["parent_process_guid"], optional=True)
    if values["destination_ip"]:
        try:
            values["destination_ip"] = str(ipaddress.ip_address(values["destination_ip"]))
        except ValueError:
            raise InputError("Invalid destination IP address.") from None
    initiated = raw.get("initiated")
    if initiated is not None and not isinstance(initiated, bool):
        raise InputError("Initiated must be true, false or null.")
    values["initiated"] = initiated
    if values["event_id"] == 11 and not values["target_filename"]:
        raise InputError("FileCreate requires TargetFilename.")
    return Event(**values)
