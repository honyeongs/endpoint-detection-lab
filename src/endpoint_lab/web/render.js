export const $ = (id) => document.getElementById(id);
export const visible = (value) =>
  String(value ?? "").replace(
    /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
export const basename = (value) =>
  visible(
    String(value ?? "")
      .split(/[\\/]/)
      .pop(),
  ) || "알 수 없음";
export const clock = (value) =>
  value ? value.slice(11, 23) : "생성 이벤트 없음";
export function el(tag, value = "", className = "") {
  const node = document.createElement(tag);
  node.textContent = visible(value);
  if (className) node.className = className;
  return node;
}
export function badge(level) {
  const node = el("span", level === "high" ? "높음" : "주의", "badge");
  node.dataset.level = level;
  return node;
}
export function table(headers, rows) {
  const node = el("table");
  const head = el("thead");
  const heading = el("tr");
  headers.forEach((header) => heading.append(el("th", header)));
  head.append(heading);
  const body = el("tbody");
  for (const row of rows) {
    const tr = el("tr");
    for (const value of row) {
      const td = el("td");
      td.append(
        value instanceof Node ? value : document.createTextNode(visible(value)),
      );
      tr.append(td);
    }
    body.append(tr);
  }
  node.append(head, body);
  return node;
}
export function linkButton(label, callback) {
  const button = el("button", label, "text-button");
  button.type = "button";
  button.addEventListener("click", callback);
  return button;
}
export function details(title, values) {
  $("detail").hidden = false;
  $("detail-title").textContent = title;
  const dl = el("dl", "", "detail-grid");
  for (const [name, value] of Object.entries(values)) {
    const content = el("dd");
    content.textContent = typeof value === "object"
      ? JSON.stringify(value, (_key, item) => typeof item === "string" ? visible(item) : item, 2)
      : visible(value);
    dl.append(el("dt", name), content);
  }
  $("detail-content").replaceChildren(dl);
}
export function summary(report) {
  $("analysis").hidden = false;
  for (const field of ["events", "processes", "alerts", "suppressed"])
    $(`metric-${field}`).textContent = report.summary[field].toLocaleString();
  $("nav-alerts").textContent = report.alert_count;
  $("replay").max = report.replay.total;
  $("replay").value = report.replay.analyzed;
  $("replay-position").textContent =
    `${report.replay.analyzed} / ${report.replay.total}`;
  const missing = report.coverage
    .filter((rule) => rule.missing_event_ids.length)
    .map((rule) => `${rule.rule_id}: ${rule.missing_event_ids.join(",")}`);
  const notes = [];
  if (report.quality === "empty") notes.push("분석 이벤트 없음");
  if (report.input.unsupported_events)
    notes.push(`지원 범위 밖 이벤트 ${report.input.unsupported_events}개`);
  if (report.input.foreign_provider_events)
    notes.push(`다른 Provider ${report.input.foreign_provider_events}개`);
  if (report.input.duplicate_events)
    notes.push(`동일 이벤트 중복 제외 ${report.input.duplicate_events}개`);
  if (report.graph_issues.count)
    notes.push(`프로세스 연결 경고 ${report.graph_issues.count}개`);
  if (missing.length)
    notes.push(`입력에 없는 이벤트 유형 (${missing.join(" · ")})`);
  if (report.alerts_truncated || report.suppressed_truncated)
    notes.push("탐지·제외 목록 표시 한도 500개; 총계는 전체 입력 기준");
  $("quality").textContent = notes.join(" / ");
  $("quality").hidden = notes.length === 0;
}
export function matches(item, query, host) {
  return (
    (!host || item.host === host) &&
    (!query ||
      visible(JSON.stringify(item)).toLocaleLowerCase().includes(query))
  );
}
export function paginate(items, state) {
  const size = 50;
  state.page = Math.max(
    0,
    Math.min(state.page, Math.ceil(items.length / size) - 1),
  );
  $("pagination").hidden = items.length <= size;
  $("previous").disabled = state.page === 0;
  $("next").disabled = (state.page + 1) * size >= items.length;
  $("page-position").textContent =
    `${state.page + 1} / ${Math.max(1, Math.ceil(items.length / size))}`;
  $("view-count").textContent = `${items.length.toLocaleString()}개`;
  return items.slice(state.page * size, (state.page + 1) * size);
}
