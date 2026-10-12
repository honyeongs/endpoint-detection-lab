import {
  $,
  el,
  table,
  badge,
  basename,
  clock,
  details,
  linkButton,
  matches,
  paginate,
} from "./render.js";

export function showAlert(alert, report, rules) {
  const rule = rules.find((rule) => rule.id === alert.rule_id);
  details(alert.name, {
    규칙: alert.rule_id,
    "시각 (UTC)": alert.timestamp,
    호스트: alert.host,
    "실행 경로": alert.image,
    "탐지 이유": alert.reason,
    "일치한 근거": alert.evidence,
    "정상 작업 가능성": rule?.false_positives || "",
    "탐지 한계": rule?.limitations || "",
    "관련 이벤트": report.events
      .filter((event) => alert.related_events.includes(event.key))
      .map((event) => ({
        event_id: event.event_id,
        record_id: event.record_id,
        timestamp: event.timestamp,
        image: event.image,
      })),
    ...(alert.suppression ? { "제외 정책": alert.suppression } : {}),
  });
}
export function renderAlerts(state) {
  const { report, rules } = state;
  const items = report.alerts.filter(
    (alert) =>
      matches(alert, state.query, state.host) &&
      (!state.severity || alert.severity === state.severity),
  );
  const rows = paginate(items, state).map((alert) => [
    badge(alert.severity),
    alert.rule_id,
    linkButton(alert.name, () => showAlert(alert, report, rules)),
    basename(alert.image),
    alert.host,
    clock(alert.timestamp),
  ]);
  $("alert-list").replaceChildren(
    rows.length
      ? table(
          ["위험도", "규칙", "탐지 사건", "프로세스", "호스트", "시각 UTC"],
          rows,
        )
      : el("p", "선택 범위에서 발견된 징후 없음 · 안전 판정 아님", "empty"),
  );
  $("suppressed-section").hidden = report.suppressed_count === 0;
  $("suppressed-summary").textContent =
    `정책 제외 ${report.suppressed_count}개`;
  $("suppressed-list").replaceChildren(
    ...report.suppressed.map((alert) =>
      linkButton(
        `${alert.rule_id} · ${basename(alert.image)} · ${alert.suppression}`,
        () => showAlert(alert, report, rules),
      ),
    ),
  );
}
export function renderTimeline(state) {
  const names = {
    1: "ProcessCreate",
    3: "NetworkConnect",
    5: "ProcessTerminate",
    11: "FileCreate",
  };
  const items = state.report.events.filter((event) =>
    matches(event, state.query, state.host),
  );
  const rows = paginate(items, state).map((event) => [
    clock(event.timestamp),
    `${event.event_id} · ${names[event.event_id]}`,
    linkButton(basename(event.image), () => details("이벤트 원문 필드", event)),
    event.pid,
    event.host,
    event.event_id === 3
      ? `${event.destination_ip}:${event.destination_port}`
      : event.event_id === 11
        ? event.target_filename
        : event.command_line || event.parent_image || "-",
    event.alert_count,
  ]);
  $("timeline-list").replaceChildren(
    rows.length
      ? table(
          [
            "시각 UTC",
            "이벤트",
            "프로세스",
            "PID",
            "호스트",
            "메타데이터",
            "징후",
          ],
          rows,
        )
      : el("p", "선택 범위에 이벤트 없음", "empty"),
  );
}
