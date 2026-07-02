# mock-vuln-npm

**Research mock repository** for H2 stage v4 pilot (thesis: Fragmented Fixes).
NOT a real vulnerable npm project — pinned deps are for pilot experiment only.

## Purpose

Test whether canonical normalize + sources-labels adds measurable value over a
multi-source scanner's raw output, in a CI/CD enforcing gate (pre-merge
required status check).

## Setup for real GitHub Actions run

1. Push this directory to a public GitHub repository (e.g., `mock-vuln-npm`)
2. Add branch protection on `main` requiring `canonical-lookup / canonical` status check
3. Open a PR modifying `package-lock.json` — workflow triggers
4. Workflow runs 3 arms (nvd_only / scanner_native / canonical), emits status checks
5. PR comment shows attribution decomposition

## Structure

```
mock-vuln-npm/
├── package.json                  # 3 pinned vulnerable deps (pilot tuples)
├── package-lock.json             # locked to vulnerable versions
├── canonical_data/
│   └── unified_canonical.json    # canonical snapshot (from thesis parent repo)
├── tests/
│   └── pilot_tuples.json         # 3 stratified GT tuples
└── .github/
    ├── workflows/
    │   └── pre-merge.yml         # 3-arm attribution decomposition
    └── actions/
        └── canonical-lookup/
            ├── action.yml
            └── canonical_lookup.py
```

## Pilot tuples (v4 stratified selection)

| Stratum | CVE | Package | GT fix | Expected outcome |
|---|---|---|---|---|
| NVD-hard | CVE-2026-25228 | signalk-server | 2.20.3 | scanner_native gains coverage over nvd_only |
| GHSA-hard | CVE-2026-33285 | liquidjs | 10.25.1 | scanner_native may miss (OSV.dev import lag), canonical catches via NVD |
| Baseline | CVE-2026-31998 | openclaw | 2026.5.24-beta.2 | canonical snapshot may lag pre-release |

## Local pilot execution (no GitHub Actions needed)

See `../Test_h2_stage_v4_pilot.py` in parent repo for local API-based pilot
(uses OSV.dev API as scanner_native proxy in absence of local Grype install).
