"""Original synthetic metadata only. Nothing here executes commands or opens connections."""
from datetime import datetime, timedelta, timezone
import uuid

from .policy import ADMIN_COMMAND, TUNED

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CHROME = r"C:\Program Files\LabBrowser\chrome.exe"
OFFICE = r"C:\Program Files\LabOffice\winword.exe"
TEMP_EXE = r"C:\Users\lab\AppData\Local\Temp\invoice.exe"


def process(number, *, second=0, host="lab-01", image=CHROME, pid=None, parent=0, parent_image="", command=""):
    return dict(event_id=1, timestamp=(BASE + timedelta(seconds=second)).isoformat(), host=host,
                process_guid=str(uuid.UUID(int=number)), image=image, record_id=number,
                pid=pid or number * 10, parent_process_guid=str(uuid.UUID(int=parent)) if parent else "",
                parent_image=parent_image, command_line=command, user="LAB\\synthetic")


def connection(start, record, *, second=10, address="8.8.8.8", initiated=True, host=None):
    return dict(event_id=3, timestamp=(BASE + timedelta(seconds=second)).isoformat(),
                host=host or start["host"], process_guid=start["process_guid"], image=start["image"],
                pid=start["pid"], record_id=record, destination_ip=address, destination_port=443, initiated=initiated)


def created(writer, record, *, second=5, target=TEMP_EXE):
    return dict(event_id=11, timestamp=(BASE + timedelta(seconds=second)).isoformat(), host=writer["host"],
                process_guid=writer["process_guid"], image=writer["image"], pid=writer["pid"],
                record_id=record, target_filename=target)


def build_cases():
    cases = []

    def case(identifier, title, events, expected=()):
        cases.append(dict(id=identifier, name=title, synthetic=True, events=events,
                          expected=[dict(rule_id=rule, record_id=record) for rule, record in expected]))

    root = process(1, image=r"C:\Windows\explorer.exe")
    browser = process(2, second=1, parent=1, parent_image=root["image"])
    file = created(browser, 3)
    payload = process(4, second=10, image=TEMP_EXE, parent=2, parent_image=browser["image"])
    office = process(5, second=20, image=OFFICE, parent=1, parent_image=root["image"])
    shell = process(6, second=30, image=POWERSHELL, parent=5, parent_image=OFFICE,
                    command="powershell.exe -EncodedCommand SYNTHETIC_UNTRUSTED_INPUT")
    network = connection(shell, 7, second=45)
    ended = dict(event_id=5, timestamp=(BASE + timedelta(seconds=60)).isoformat(), host=shell["host"],
                 process_guid=shell["process_guid"], image=shell["image"], pid=shell["pid"], record_id=8)
    case("incident-chain", "문서 실행·임시 파일·외부 연결", [root, browser, file, payload, office, shell, network, ended],
         [("EDL-001", 4), ("EDL-005", 4), ("EDL-002", 6), ("EDL-003", 6), ("EDL-004", 7)])
    browser = process(1)
    case("normal-browser", "정상 브라우저 연결", [browser, connection(browser, 2)])
    admin = process(1, image=POWERSHELL, host="lab-admin", command=ADMIN_COMMAND)
    case("normal-admin", "승인된 관리 작업 · 오탐 비교", [admin, connection(admin, 2)])
    case("temp-executable", "임시 경로 실행", [process(1, image=TEMP_EXE)], [("EDL-001", 1)])
    office = process(1, image=OFFICE)
    child = process(2, second=1, image=r"C:\Windows\System32\cmd.exe", parent=1, parent_image=OFFICE)
    case("office-shell", "문서 프로그램의 셸 생성", [office, child], [("EDL-002", 2)])
    encoded = process(1, image=POWERSHELL, command="powershell.exe -enc SYNTHETIC_UNTRUSTED_INPUT")
    case("encoded-powershell", "인코딩 옵션 실행", [encoded], [("EDL-003", 1)])
    script = process(1, image=r"C:\Windows\System32\wscript.exe")
    case("script-egress", "스크립트의 외부 연결", [script, connection(script, 2)], [("EDL-004", 2)])
    writer = process(1)
    case("created-then-run", "생성된 실행 파일 실행", [writer, created(writer, 2), process(3, second=10, image=TEMP_EXE)],
         [("EDL-001", 3), ("EDL-005", 3)])
    ps = process(1, image=POWERSHELL)
    case("delayed-egress", "120초 경계 밖 연결", [ps, connection(ps, 2, second=121)])
    case("private-egress", "사설 주소 연결", [ps, connection(ps, 2, address="10.0.0.20")])
    case("delayed-file", "300초 경계 밖 파일 실행", [writer, created(writer, 2, second=5), process(3, second=306, image=TEMP_EXE)],
         [("EDL-001", 3)])
    case("cross-host", "다른 호스트의 같은 GUID", [ps, connection(ps, 2, host="lab-other")])
    old = process(1, pid=600)
    reused = process(2, second=2, image=POWERSHELL, pid=600)
    case("pid-reuse", "PID 재사용 · GUID 분리", [old, reused, connection(old, 3)])
    case("office-not-shell", "문서 프로그램의 정상 자식", [office, process(2, second=1, image=r"C:\Windows\notepad.exe", parent=1)])
    case("inbound-connection", "인바운드 연결 제외", [ps, connection(ps, 2, initiated=False)])
    case("parent-metadata", "부모 이벤트 없는 선언 메타데이터", [process(2, image=r"C:\Windows\cmd.exe", parent=1, parent_image=OFFICE)],
         [("EDL-002", 2)])
    case("boundary-egress", "120초 경계 포함", [ps, connection(ps, 2, second=120)], [("EDL-004", 2)])
    case("boundary-file", "300초 경계 포함", [writer, created(writer, 2, second=5), process(3, second=305, image=TEMP_EXE)],
         [("EDL-001", 3), ("EDL-005", 3)])
    return cases


def get_case(identifier):
    return next((case for case in build_cases() if case["id"] == identifier), None)


def scenario_catalog():
    return [dict(id=case["id"], name=case["name"], events=len(case["events"]), synthetic=True) for case in build_cases()]


def tuned_policy():
    return TUNED
