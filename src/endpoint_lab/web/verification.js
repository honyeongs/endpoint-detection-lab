import { $, el, table, linkButton, details } from "./render.js";

const percent = (value) =>
  value === null ? "-" : `${(value * 100).toFixed(1)}%`;
export function renderVerification(comparison, openCase) {
  const { baseline, tuned } = comparison;
  const content = [
    el(
      "p",
      `직접 작성한 합성 시나리오 ${tuned.case_count}개 · 실제 환경 성능 측정 아님`,
      "verification-notice",
    ),
  ];
  content.push(
    table(
      ["정책", "TP", "FP", "FN", "정밀도", "재현율", "기대 결과 일치"],
      [
        [
          "기본",
          baseline.totals.tp,
          baseline.totals.fp,
          baseline.totals.fn,
          percent(baseline.precision),
          percent(baseline.recall),
          `${baseline.passed_cases}/${baseline.case_count}`,
        ],
        [
          "오탐 조정",
          tuned.totals.tp,
          tuned.totals.fp,
          tuned.totals.fn,
          percent(tuned.precision),
          percent(tuned.recall),
          `${tuned.passed_cases}/${tuned.case_count}`,
        ],
      ],
    ),
  );
  content.push(el("h3", "규칙별 비교", "subheading"));
  content.push(
    table(
      ["규칙", "기본 TP / FP / FN", "조정 TP / FP / FN"],
      baseline.per_rule.map((row, index) => {
        const next = tuned.per_rule[index];
        return [
          row.rule_id,
          `${row.tp} / ${row.fp} / ${row.fn}`,
          `${next.tp} / ${next.fp} / ${next.fn}`,
        ];
      }),
    ),
  );
  content.push(el("h3", "검증 시나리오", "subheading"));
  content.push(
    table(
      ["시나리오", "기본", "오탐 조정", "근거"],
      baseline.cases.map((row, index) => {
        const next = tuned.cases[index];
        return [
          linkButton(row.name, () => openCase(row.id)),
          row.passed ? "일치" : `FP ${row.fp} / FN ${row.fn}`,
          next.passed ? "일치" : `FP ${next.fp} / FN ${next.fn}`,
          linkButton("기대·실제 비교", () =>
            details(row.name, {
              "기대 (규칙, RecordID)": row.expected,
              "기본 실제": row.actual,
              "조정 실제": next.actual,
            }),
          ),
        ];
      }),
    ),
  );
  content.push(
    el(
      "p",
      "TP/FP/FN: 시나리오별 규칙·대상 이벤트 쌍. 예외와 일치해도 안전성은 보장되지 않음.",
      "muted",
    ),
  );
  $("verification").replaceChildren(...content);
}
export function renderRules(rules) {
  $("rule-list").replaceChildren(
    ...rules.map((rule) => {
      const section = el("article", "", "rule-row");
      section.append(
        el("span", rule.id, "rule-id"),
        el("h3", rule.name),
        el("p", rule.description),
        el(
          "p",
          `필요 이벤트: ${rule.required.join(", ")} / 시간 범위: ${rule.window_seconds}초`,
          "muted",
        ),
        el("p", `정상 작업 가능성: ${rule.false_positives}`, "muted"),
        el("p", `한계: ${rule.limitations}`, "muted"),
      );
      return section;
    }),
  );
}
