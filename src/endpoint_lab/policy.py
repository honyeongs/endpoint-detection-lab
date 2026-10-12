from .catalog import BY_ID
from .limits import InputError
from .model import windows_path

ADMIN_COMMAND = 'powershell.exe -EncodedCommand SYNTHETIC_APPROVED_ADMIN_TASK'
TUNED = {"exclusions": [dict(rule_id=rule, host="lab-admin", command_line=ADMIN_COMMAND)
                         for rule in ["EDL-003", "EDL-004"]]}


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) != {"exclusions"}:
        raise InputError("Policy must contain only exclusions.")
    exclusions = policy["exclusions"]
    if not isinstance(exclusions, list) or len(exclusions) > 100:
        raise InputError("At most 100 exact-match exclusions are accepted.")
    allowed = {"rule_id", "host", "image", "command_line", "parent_image"}
    for entry in exclusions:
        if not isinstance(entry, dict) or set(entry) - allowed or entry.get("rule_id") not in BY_ID:
            raise InputError("Unknown rule or exclusion field.")
        if not set(entry) & {"image", "command_line", "parent_image"}:
            raise InputError("An exclusion needs an exact image, command_line or parent_image match.")
        if any(not isinstance(v, str) or not v or len(v) > 4096 for v in entry.values()):
            raise InputError("Exclusion values must be nonempty strings up to 4096 characters.")
    return exclusions


def suppression(rule_id, event, exclusions):
    for index, entry in enumerate(exclusions):
        if entry["rule_id"] != rule_id:
            continue
        matches = True
        for field, expected in entry.items():
            if field == "rule_id":
                continue
            actual = getattr(event, field)
            if field in {"image", "parent_image"}:
                actual, expected = windows_path(actual), windows_path(expected)
            elif field == "host":
                actual, expected = actual.casefold(), expected.casefold()
            matches &= actual == expected
        if matches:
            return f"exact-exclusion-{index + 1}"
    return None
