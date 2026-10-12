# 입력 형식

## 지원 범위

- Sysmon XML의 Event ID `1` ProcessCreate, `3` NetworkConnect, `5` ProcessTerminate, `11` FileCreate.
- `<Events>` 안의 Event 목록 또는 단일 `<Event>`, 표준 Windows 이벤트 namespace 또는 namespace 없음.
- Provider가 `Microsoft-Windows-Sysmon`이 아닌 이벤트와 범위 밖 Event ID는 제외 수로 표시한다.
- JSON은 아래 정규화 이벤트 객체의 배열이다. JSONL·EVTX·CSV·보고서 JSON은 입력 형식이 아니다.
- 중복 키·알 수 없는 필드·정답 라벨·잘못된 GUID·필드 타입은 거부한다. 파싱 실패 시 부분 성공 보고서를 만들지 않는다.

```json
[
  {
    "event_id": 1,
    "timestamp": "2026-01-01T00:00:00Z",
    "host": "lab-01",
    "process_guid": "00000000-0000-0000-0000-000000000001",
    "image": "C:\\Windows\\notepad.exe",
    "record_id": 1,
    "pid": 400,
    "parent_process_guid": "",
    "parent_image": "C:\\Windows\\explorer.exe",
    "command_line": "notepad.exe",
    "user": "LAB\\synthetic"
  }
]
```

필수 공통 필드: `event_id`, `timestamp`, `host`, `process_guid`, `image`.
선택 필드: `record_id`, `pid`, `parent_process_guid`, `parent_image`, `command_line`, `user`,
`target_filename`, `destination_ip`, `destination_port`, `initiated`.
FileCreate에는 `target_filename`이 필요하다. 외부 연결 규칙에는 유효한 IP와 `initiated: true`가 필요하다.
선택 문자열의 기본값은 빈 문자열, 선택 정수는 0, `initiated`는 null이다.

UTC로 정규화한다. 시간대 없는 Sysmon `UtcTime`은 UTC로 해석하고 마이크로초까지 유지한다.
호스트·GUID는 대소문자를 정규화한다. 실행 경로 비교는 Windows 경로 정규화이며 실제 디스크 경로나 파일을 조회하지 않는다.
EDL-004는 같은 GUID·호스트·이미지의 생성 이벤트가 있어야 하고, 알려진 종료 이후 연결은 제외한다.
같은 GUID의 서로 다른 생성 이벤트는 모순으로 거부한다. 원본 로그의 진본성은 인증하지 않는다.

## 실제 Windows 로그 내보내기

Sysmon은 이 저장소에 포함하지 않는다. 필요하다면 [Microsoft 공식 배포처](https://learn.microsoft.com/sysinternals/downloads/sysmon)에서
약관을 확인하고 별도로 준비한다. Event ID 3 네트워크 로깅은 기본적으로 꺼져 있으므로 필요한 수집 설정을 확인해야 한다.
이 앱은 Sysmon을 설치하거나 설정을 변경하지 않는다.

권한 있는 본인 장비에서 이미 수집된 로그를 내보내는 예시:

```powershell
$events = Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1,3,5,11
} -MaxEvents 1000
$xml = '<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join "`n") + '</Events>'
[IO.File]::WriteAllText((Join-Path $PWD 'sysmon-export.xml'), $xml, [Text.UTF8Encoding]::new($false))
```

이 명령은 문서 예시이며 개발 검증 중 실제 장비에서 실행하지 않았다.
회사 장비는 사전 승인을 받는다. 사용자 이름·경로·명령줄에 민감정보가 있을 수 있으므로 로그·보고서를 공개하지 않는다.
호스트 시계 동기화와 수집의 완전성은 운영 전제이며 이 분석기가 보장하는 항목이 아니다.
