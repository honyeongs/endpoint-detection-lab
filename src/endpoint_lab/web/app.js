import { $, el, visible, summary } from "./render.js";
import { renderAlerts, renderTimeline } from "./timeline.js";
import { renderProcesses } from "./processes.js";
import { renderRules, renderVerification } from "./verification.js";

const state = {
  source: null,
  report: null,
  rules: [],
  comparison: null,
  view: "alerts",
  policy: "baseline",
  query: "",
  host: "",
  severity: "",
  page: 0,
  playing: false,
  playbackEpoch: 0,
  busy: false,
  controller: null,
  epoch: 0,
};
const titles = {
  alerts: "탐지 사건",
  timeline: "사건 타임라인",
  processes: "프로세스 트리",
  validation: "탐지 규칙 검증",
  rules: "직접 작성한 탐지 규칙",
};
function controls() {
  $("cancel").hidden = !state.busy;
  $("scenario").disabled = state.busy;
  $("file").disabled = state.busy;
  $("export").disabled = !state.report || state.busy;
  $("step").disabled =
    !state.report ||
    state.busy ||
    state.report.replay.analyzed >= state.report.replay.total;
  $("play").disabled =
    !state.report ||
    (state.busy && !state.playing) ||
    state.report.replay.total === 0;
  $("play-icon").src = `/assets/${state.playing ? "pause" : "play"}.svg`;
  $("play").title = state.playing ? "일시 정지" : "재생";
  $("play").setAttribute("aria-label", $("play").title);
  $("replay").disabled = !state.report || state.busy;
  document.querySelectorAll("[data-policy]").forEach((button) => {
    button.disabled = state.busy;
    button.setAttribute(
      "aria-pressed",
      String(button.dataset.policy === state.policy),
    );
  });
  $("analysis").setAttribute("aria-busy", String(state.busy));
}
function render() {
  $("view-title").textContent = titles[state.view];
  $("view-count").textContent = "";
  $("filters").hidden =
    !state.report || !["alerts", "timeline", "processes"].includes(state.view);
  $("severity").hidden = state.view !== "alerts";
  $("pagination").hidden = true;
  document
    .querySelectorAll("[data-view]")
    .forEach((button) =>
      button.setAttribute(
        "aria-pressed",
        String(button.dataset.view === state.view),
      ),
    );
  for (const view of Object.keys(titles))
    $(`${view}-view`).hidden = state.view !== view;
  if (state.view === "validation") {
    if (state.comparison)
      renderVerification(state.comparison, async (id) => {
        setView("alerts");
        await openScenario(id);
      });
  } else if (state.view === "rules") renderRules(state.rules);
  else if (state.report) {
    if (state.view === "alerts") renderAlerts(state);
    if (state.view === "timeline") renderTimeline(state);
    if (state.view === "processes") renderProcesses(state);
  }
  controls();
}
function setView(view) {
  stop();
  state.view = view;
  state.page = 0;
  $("detail").hidden = true;
  render();
}
function stop() {
  state.playing = false;
  state.playbackEpoch++;
  controls();
}
async function analyze(count) {
  if (!state.source) return false;
  state.controller?.abort();
  const controller = new AbortController();
  state.controller = controller;
  const epoch = ++state.epoch;
  state.busy = true;
  $("status").textContent = "분석 중";
  controls();
  try {
    const headers = {
      "Content-Type": "application/octet-stream",
      "X-Lab-Policy": state.policy,
    };
    if (count !== undefined) headers["X-Replay-Count"] = String(count);
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers,
      body: state.source,
      signal: controller.signal,
    });
    const result = await response.json();
    if (epoch !== state.epoch) return false;
    if (!response.ok) throw new Error(result.error || "분석 실패");
    state.report = result;
    $("detail").hidden = true;
    summary(result);
    const previousHost = state.host;
    $("host").replaceChildren(el("option", "전체 호스트"));
    $("host").firstChild.value = "";
    [...new Set(result.events.map((event) => event.host))]
      .sort()
      .forEach((host) => {
        const option = el("option", host);
        option.value = host;
        $("host").append(option);
      });
    $("host").value = previousHost;
    if ($("host").selectedIndex < 0) $("host").selectedIndex = 0;
    state.host = $("host").value;
    $("status").textContent =
      result.quality === "partial"
        ? "분석 완료 · 데이터 경고 있음"
        : "분석 완료";
    render();
    return true;
  } catch (error) {
    if (epoch === state.epoch)
      $("status").textContent =
        error.name === "AbortError" ? "분석 취소됨" : error.message;
    return false;
  } finally {
    if (epoch === state.epoch) {
      state.busy = false;
      state.controller = null;
      controls();
    }
  }
}
function clearSource(name, synthetic) {
  stop();
  state.controller?.abort();
  state.controller = null;
  state.epoch++;
  state.busy = false;
  state.report = null;
  state.source = null;
  state.page = 0;
  state.query = state.host = state.severity = "";
  $("search").value = $("host").value = $("severity").value = "";
  $("source-name").textContent = visible(name);
  $("data-label").textContent = synthetic
    ? "직접 작성한 합성 데이터"
    : "사용자 선택 로그";
  $("analysis").hidden = $("detail").hidden = true;
  $("nav-alerts").textContent = "0";
  ["alert-list", "timeline-list", "process-list"].forEach((id) =>
    $(id).replaceChildren(),
  );
  render();
}
async function openScenario(id) {
  clearSource("합성 시나리오 준비 중", true);
  const epoch = state.epoch;
  state.busy = true;
  const controller = new AbortController();
  state.controller = controller;
  controls();
  try {
    const response = await fetch(`/api/scenarios/${encodeURIComponent(id)}`, {
      signal: controller.signal,
    });
    const source = await response.json();
    if (epoch !== state.epoch) return;
    if (!response.ok) throw new Error(source.error || "시나리오 로드 실패");
    $("scenario").value = id;
    $("source-name").textContent = source.name;
    state.source = new Blob([JSON.stringify(source.events)], {
      type: "application/octet-stream",
    });
    await analyze();
  } catch (error) {
    if (epoch === state.epoch) {
      $("status").textContent =
        error.name === "AbortError" ? "분석 취소됨" : error.message;
      state.busy = false;
      state.controller = null;
      controls();
    }
  }
}
async function playback() {
  if (state.playing) {
    stop();
    return;
  }
  if (!state.report) return;
  state.playing = true;
  const token = ++state.playbackEpoch;
  if (
    state.report.replay.analyzed === state.report.replay.total &&
    !(await analyze(0))
  ) {
    if (token === state.playbackEpoch) stop();
    return;
  }
  controls();
  while (
    state.playing &&
    token === state.playbackEpoch &&
    state.report &&
    state.report.replay.analyzed < state.report.replay.total
  ) {
    if (!(await analyze(state.report.replay.analyzed + 1))) break;
    await new Promise((resolve) => setTimeout(resolve, 650));
  }
  if (token === state.playbackEpoch) stop();
}
$("scenario").addEventListener("change", () =>
  openScenario($("scenario").value),
);
$("file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  clearSource(file.name, false);
  if (file.size > 8 * 1024 * 1024) {
    $("status").textContent = "8 MiB 이하 로그만 분석할 수 있습니다.";
    return;
  }
  state.source = file;
  await analyze();
});
$("reset").addEventListener("click", () => {
  $("file").value = "";
  state.policy = "baseline";
  openScenario("incident-chain");
});
$("cancel").addEventListener("click", () => {
  stop();
  state.controller?.abort();
});
$("play").addEventListener("click", playback);
$("step").addEventListener("click", () => {
  stop();
  analyze(state.report.replay.analyzed + 1);
});
$("replay").addEventListener("input", () => {
  $("replay-position").textContent =
    `${$("replay").value} / ${$("replay").max}`;
});
$("replay").addEventListener("change", () => {
  stop();
  state.page = 0;
  analyze(Number($("replay").value));
});
document
  .querySelectorAll("[data-view]")
  .forEach((button) =>
    button.addEventListener("click", () => setView(button.dataset.view)),
  );
document.querySelectorAll("[data-policy]").forEach((button) =>
  button.addEventListener("click", () => {
    stop();
    state.policy = button.dataset.policy;
    analyze(state.report?.replay.analyzed);
  }),
);
for (const id of ["search", "host", "severity"])
  $(id).addEventListener(id === "search" ? "input" : "change", () => {
    state.query = $("search").value.toLocaleLowerCase();
    state.host = $("host").value;
    state.severity = $("severity").value;
    state.page = 0;
    render();
  });
$("previous").addEventListener("click", () => {
  state.page--;
  render();
});
$("next").addEventListener("click", () => {
  state.page++;
  render();
});
$("close-detail").addEventListener("click", () => {
  $("detail").hidden = true;
});
$("export").addEventListener("click", () => {
  if (!state.report) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(state.report, null, 2)], {
      type: "application/json",
    }),
  );
  const anchor = el("a");
  anchor.href = url;
  anchor.download = "endpoint-lab-report.json";
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
try {
  const response = await fetch("/api/catalog");
  if (!response.ok) throw new Error("규칙 목록 로드 실패");
  const catalog = await response.json();
  state.rules = catalog.rules;
  $("scenario").replaceChildren(
    ...catalog.scenarios.map((caseInfo) => {
      const option = el("option", caseInfo.name);
      option.value = caseInfo.id;
      return option;
    }),
  );
  await openScenario("incident-chain");
  const verification = await fetch("/api/validation");
  if (!verification.ok) throw new Error("검증 데이터 로드 실패");
  state.comparison = await verification.json();
  render();
} catch (error) {
  $("status").textContent = error.message;
}
