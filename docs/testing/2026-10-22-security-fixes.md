# 로컬 공개 테스트 기록

- 저장소: `endpoint-detection-lab`
- 실행 시각(UTC): `2026-10-22T00:18:33.142705+00:00`
- 환경: Windows / Python 3.14.7
- 검사 당시 기준 커밋: `4dfca7d11501a485e5fcc953c01cc2eb4d7fdf02`
- 보고서는 아직 커밋되지 않은 테스트 실행기 변경을 포함한 작업 트리를 검사한 결과입니다.
- 검사 대상 파일 71개의 정규화 SHA-256: `c5fa47bacf540fed2b7cbc1fb82b9f40b2dbca381c4651b70d655ba4d1ee8472`
- 위 값은 소스 지문이며 개인 파일 해시나 디지털 서명이 아닙니다.

## 대표 시나리오 10개

기존 테스트 중 서로 다른 기능 10개를 선정하여 별도 재실행했습니다. 전체 회귀 검사와 중복되므로 독립 표본 20개로 합산하지 않습니다.

- **P01: Sysmon XML and normalized JSON parity**
  결과: `passed`, 3.366 ms. 재현 대상: `tests.test_parsing.ParsingTests.test_json_xml_equivalence`.
- **P02: All five original indicators in an incident chain**
  결과: `passed`, 1.065 ms. 재현 대상: `tests.test_detection.DetectionTests.test_five_original_rules`.
- **P03: Synthetic truth validation and tuning comparison**
  결과: `passed`, 7.79 ms. 재현 대상: `tests.test_detection.DetectionTests.test_all_tuned_ground_truth_cases`.
- **P04: PID reuse does not link different GUIDs**
  결과: `passed`, 0.309 ms. 재현 대상: `tests.test_detection.DetectionTests.test_guid_not_pid`.
- **P05: Host isolation in process correlation**
  결과: `passed`, 0.239 ms. 재현 대상: `tests.test_detection.DetectionTests.test_cross_host_isolation`.
- **P06: Connection time direction and inclusive boundary**
  결과: `passed`, 0.634 ms. 재현 대상: `tests.test_detection.DetectionTests.test_future_connection_and_boundary`.
- **P07: Exact exclusions retain suppressed evidence**
  결과: `passed`, 0.337 ms. 재현 대상: `tests.test_detection.DetectionTests.test_tuning_records_suppressed_alerts`.
- **P08: DTD and internal/external entities rejected**
  결과: `passed`, 0.143 ms. 재현 대상: `tests.test_parsing.ParsingTests.test_dtd_and_entity_rejected`.
- **P09: Replay prefix changes analyzed events**
  결과: `passed`, 1.466 ms. 재현 대상: `tests.test_detection.DetectionTests.test_replay_prefix`.
- **P10: CLI output never overwrites the input**
  결과: `passed`, 16.262 ms. 재현 대상: `tests.test_cli.CliTests.test_no_overwrite`.

## 전체 자동 테스트

실행 84개: 통과 83, 실패 0, 오류 0, 건너뜀 1, fixture 오류 0.
전체 테스트별 결과와 소요 시간은 같은 폴더의 JSON에 기록했습니다.
- 건너뜀 사유 코드 `symlink_privilege`: 1개.

## 웹 검증

이번 실행에는 웹 검증을 포함하지 않았습니다.

## 공개 정보 범위

개인 폴더를 임의로 탐색하지 않았습니다. 테스트 코드가 지정한 프로젝트 파일과 격리된 임시 테스트 자료만 사용했습니다.
로그·계정·호스트·IP·명령줄·DB·세션/소스 토큰·예외 상세·절대 경로·브라우저 화면은 공개 보고서에서 제외했습니다.
기존 샘플의 이름은 가상 식별자이며 실제 개인정보를 단순 가명 처리한 자료가 아닙니다.
임시 DB 비밀번호·암호화 키·인증 토큰은 테스트 실행 중 생성되거나 코드의 명시적 테스트용 값이며 보고서로 내보내지 않습니다.

## 한계

- All telemetry in this run is original synthetic Sysmon-shaped XML/JSON, not logs collected from a real endpoint.
- Synthetic TP/FP/FN measures functional regression only, not independent field detection accuracy.
- No Sysmon installation, malware execution, event collection agent or automatic blocking is performed.
- Windows symbolic-link cases may be skipped when the account lacks the required privilege.
- 성공은 해당 테스트의 기대 동작 일치이며 안전 인증·무결점·법적 적합성 보증이 아닙니다.
- 소요 시간은 이 PC의 단일 실행 관측값이며 성능 벤치마크가 아닙니다.
- 이 문서의 로컬 결과와 GitHub Actions의 원격 결과는 별개입니다.

## 재현

```console
python tools/run_portfolio_validation.py --suite all --browser --output reports/local-validation.json
```

Python 및 선택 의존성과 Playwright/Chromium 설치 방법은 README를 참고하세요.
대표 10개만 실행: `python tools/run_portfolio_validation.py --suite portfolio`.
개별 시나리오는 위 테스트 ID를 `python -m unittest <test_id> -v`로 실행할 수 있습니다.
PostgreSQL은 기본적으로 실행하지 않습니다. 운영 DB가 아닌 별도 테스트 DB에만 명시적으로 허용하세요.
