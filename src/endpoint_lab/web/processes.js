import {
  $,
  el,
  basename,
  clock,
  details,
  linkButton,
  matches,
  paginate,
} from "./render.js";

export function flattenProcesses(nodes) {
  const map = new Map(nodes.map((node) => [node.key, node]));
  const children = new Map();
  const roots = [];
  for (const node of nodes) {
    if (node.parent_key && map.has(node.parent_key)) {
      if (!children.has(node.parent_key)) children.set(node.parent_key, []);
      children.get(node.parent_key).push(node);
    } else roots.push(node);
  }
  const order = (a, b) =>
    (a.start || "").localeCompare(b.start || "") || a.key.localeCompare(b.key);
  roots.sort(order);
  children.forEach((items) => items.sort(order));
  const pending = roots.reverse().map((node) => ({ node, depth: 0 }));
  const flat = [];
  const visited = new Set();
  while (pending.length) {
    const item = pending.pop();
    if (visited.has(item.node.key)) continue;
    visited.add(item.node.key);
    flat.push(item);
    const nested = children.get(item.node.key) || [];
    for (let i = nested.length - 1; i >= 0; i--)
      pending.push({ node: nested[i], depth: item.depth + 1 });
  }
  return flat;
}
export function renderProcesses(state) {
  const flat = flattenProcesses(state.report.processes).filter(({ node }) =>
    matches(node, state.query, state.host),
  );
  const rows = paginate(flat, state).map(({ node, depth }) => {
    const row = el("article", "", `process-row depth-${Math.min(depth, 8)}`);
    const main = el("div");
    main.append(
      linkButton(basename(node.image), () =>
        details("프로세스 연결", {
          호스트: node.host,
          "실행 경로": node.image,
          ProcessGuid: node.process_guid,
          PID: node.pid,
          "부모 키": node.parent_key || "없음",
          "생성 시각": node.start || "생성 이벤트 없음",
          "종료 시각": node.end || "종료 이벤트 없음",
          "트리 깊이": depth,
          "탐지 징후": node.alert_count,
        }),
      ),
    );
    main.append(el("span", `PID ${node.pid || "?"} · ${node.host}`, "muted"));
    if (node.creation_missing)
      main.append(el("span", "생성 이벤트 없음", "missing"));
    const identity = el("div", node.process_guid, "guid");
    row.append(main, identity, el("span", clock(node.start), "process-time"));
    if (node.alert_count)
      row.append(el("span", `${node.alert_count}개 징후`, "process-alerts"));
    return row;
  });
  $("process-list").replaceChildren(
    ...(rows.length ? rows : [el("p", "선택 범위에 프로세스 없음", "empty")]),
  );
}
