# Security Fix Verification

Date: 2026-10-22 (Asia/Seoul). Repository: `endpoint-detection-lab`.

## Deployed Result

- URL: [public website](https://endpoint-lab-web.yao0422q.chatgpt.site/). Existing Site identity, URL and public audience were preserved.
- Successful deployment: `appgdep_6ad955effd2c819188e93eb93785eaac`.
- Saved version: `appgprj_6ad9388e57f08191bee9fe56602ee1b6~appgver_fbe39455e65081918887f8e0939fbc8e`.
- Sites source commit: `724d84599b3bfeea1fed1e19bdb7274438decc68`. This is separate from the GitHub source repository commit.
- The deployment is a small read-only public-asset Worker rather than the former static route. It does not accept analysis uploads, persist user input, proxy arbitrary destinations or add an authentication/billing backend.
- Confirmed actual document, engine-worker script and 404 responses contain CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. CSP includes `frame-ancestors 'none'` and limits Worker connections to the same origin.
- App code and the unchanged licensed runtime are gzip-packaged with their original notice files. No selected user file or original device log is packaged.
- Explicit `encodeBody: manual` prevents the hosting runtime from recompressing precompressed bytes. An intermediate NetSec rollout exposed this hosting-specific issue despite local tests passing. It was corrected in the successful deployment above and a regression check was added. Do not treat that intermediate rollout as validated.

## Verification Performed

- Final full local regression: 89 tests, 88 passed, 1 skipped, zero failures/errors. Skips: one Windows file-link privilege check; not counted as passes.

- Five Python packaging checks passed: fixed public allowlist/original bytes, checksum mismatch rejection, directory-escape rejection, input/output separation and preservation/rejection of unrelated output files.
- Five Node Worker checks passed: security headers, gzip round-trip, explicit manual encoding, bodyless HEAD/method rejection, and fixed asset paths.
- Local browser checks and a fresh unauthenticated Chromium context at the actual public URL each passed all 12 checks: actual document/Worker/error headers; blocked cross-origin framing; browser-local analysis; native Python parity/input boundaries; cancellation/recovery; manifest/icons; Windows shortcut download; desktop/390px/360px layouts; install control; offline reload/analysis; session reset; no input transmission/external app requests/page errors.
- The browser checks verify analysis still works with the Worker response CSP enforced, not only with an HTML meta policy.
- The former ten representative portfolio cases passed again. They overlap the full suite and are not extra independent samples.
- Sanitized final full local test evidence: [JSON](testing/2026-10-22-security-fixes-final.json), [readable record](testing/2026-10-22-security-fixes-final.md). Test IDs, results, counts, durations, source fingerprints and categorized skips only; no raw telemetry, exception messages, personal paths, accounts, tokens or screenshots. The [initial 84-test record](testing/2026-10-22-security-fixes.md) is retained as historical evidence.
- Each GitHub push independently reruns the configured CI jobs. Check the [Actions run](https://github.com/honyeongs/endpoint-detection-lab/actions) for the exact commit and conclusion; a local pass is not a remote CI pass.

## Reproduction and Operational Notes

The initial GitHub run blocked the new evidence filename and the migration away from the static-only manifest. The publication gate now explicitly allows only the three reviewed report filenames and validates each against the privacy schema; the Worker manifest accepts only a valid project ID and no extra fields. Five added tests verify the complete tracked set, manifest fields/types, privacy-schema enforcement, unknown JSON rejection and private-file rejection. No scanner was disabled. This follow-up changes the gate/tests/evidence, not the deployed application runtime.

See [website build instructions](WEBSITE.md). Run `python tools/build_website.py` with the reviewed runtime archive, then `python tools/build_hosting.py`, the Python/Node checks and `node tests/browser/website.mjs`. Set `SITE_URL` to the actual public URL for a post-deployment run.

The Service Worker cache version changed so previously installed apps replace older public assets. Open or reload the app once while online to receive the update. Actual Windows installation still requires the browser's user confirmation.

No external API keys are needed. Separately running SaaS/container installations must update their own checkout/image and restart; a GitHub push does not update a separate running process.

## Limits

This is targeted remediation and regression verification, not a full penetration test, hosting/OS/WASM CVE inventory, malware verdict, proof of absence of compromise or security certification. Existing local development servers remain loopback-only and must not be exposed publicly. Synthetic tests do not establish real-device detection/false-positive rates. Original third-party notices and terms remain applicable; this change is not legal advice or a licensing guarantee.
