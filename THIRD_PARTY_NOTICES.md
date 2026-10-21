# Third-party notices

Hosted browser PWA: Pyodide 0.29.5 / CPython 3.13.2 and included runtime components are distributed separately from the CLI. Original notices and source links are in [website/THIRD_PARTY.md](website/THIRD_PARTY.md) and the deployed license page. PNG/ICO app icons are color/background adaptations of the existing Lucide shield, with original notices retained. Generated runtime binaries are excluded from this GitHub checkout.

Bundled: **13 Lucide SVG icons**, from `lucide-static` version `1.55.0`.
The unmodified upstream ISC license and inherited Feather MIT notices are at
`src/endpoint_lab/web/assets/LUCIDE-LICENSE.txt`.
The exact files and SHA-256 hashes are recorded in `third-party-assets.json`.
Source and license: https://www.npmjs.com/package/lucide-static/v/1.55.0 and https://lucide.dev/license

Runtime: Python standard library only. Python/Expat/browser binaries are installed separately, not redistributed here.
Python licensing reference: https://www.python.org/about/legal/

Development/build only, installed separately: setuptools, Playwright, Bandit, Prettier and official GitHub Actions.
Their binaries/node_modules are not vendored. The asset package is not a runtime JavaScript dependency.

Not bundled: Sysmon executable/source/configuration templates, Windows software, Sigma rules,
MITRE data/rule packages, third-party malware samples, proprietary logs, fonts or brand logos.
Sysmon is referenced for interoperability only; this project is not affiliated with or endorsed by Microsoft.

The application's own source/rules/synthetic fixtures have no reuse license assigned yet.
Third-party notices do not grant a license to the application's own content.
