"""Original endpoint analyzer in browser memory; no user source evaluation."""
import json
from endpoint_lab.analysis import analyze_bytes
from endpoint_lab.catalog import RULES
from endpoint_lab.limits import InputError
from endpoint_lab.scenarios import get_case, scenario_catalog, tuned_policy
from endpoint_lab.validation import compare_policies

def dispatch(route, body, metadata, auxiliary):
    if route == "/api/health":
        data = {"status": "ready"}
    elif route == "/api/catalog":
        data = {"rules": RULES, "scenarios": scenario_catalog()}
    elif route == "/api/validation":
        data = compare_policies()
    elif route.startswith("/api/scenarios/"):
        data = get_case(route.removeprefix("/api/scenarios/"))
        if data is None:
            raise InputError("Unknown scenario")
    elif route == "/api/analyze":
        if metadata.get("policy") not in {"baseline", "tuned"}:
            raise InputError("Unknown policy")
        data = analyze_bytes(body, policy=tuned_policy() if metadata["policy"] == "tuned" else None,
                             replay_count=metadata.get("replay"))
    else:
        raise InputError("Unknown route")
    return {"status": 200, "data": data}

def _dispatch_json(route, body, metadata, auxiliary):
    try:
        result = dispatch(route, body, json.loads(metadata), auxiliary)
    except (InputError, ValueError, TypeError):
        result = {"status": 400, "data": {"error": "로그 형식·크기 또는 선택한 분석 조건이 올바르지 않습니다."}}
    return json.dumps(result, ensure_ascii=True, allow_nan=False)
