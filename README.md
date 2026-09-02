# H2 real-pipeline validation 鈥?instantiation kit

Everything the live GitHub Actions census needs. **This directory is version-controlled
in the thesis repo; the repository it becomes is separate and public.**

Target repository: **`hfgjahgf/mock-vuln-npm-h2-pilot`** 鈥?the one v1's pilot already
used. v1's own content stays in its history; this kit replaces the working tree, because
v1 ran a different data model and a different four arms (`nvd_direct` / `grype_native` /
`canonical_enrichment` / `canonical_direct`, last touched 2026-07-03).

Protocol: `schemas/H2_REAL_PIPELINE_PROTOCOL.md` (`h2-real-protocol-6`), frozen before
any run. Inputs: `H2_REAL_ENVIRONMENTS.json` (1,556 environments) and
`H2_UNIFIED_RECOMMENDATIONS.json` (the Unified arm's only source).

## What it does

Per environment 鈥?one `(package, installed_version)` pair, installed as a **top-level
direct dependency**:

```
phase 1   npm install <pkg>@<installed> --package-lock-only --ignore-scripts \
                                        --save-exact        (and verify the pin)
          npm audit --json                       -> npm_registry_audit_live
          osv-scanner scan --lockfile ... --format json  -> osv_scanner_live
          method gate, PER SCANNER: did this one name any target advisory?
          a scanner that could not RUN reports null, not an empty match list

phase 2   for each arm's recommendation:
            npm install <pkg>@<fix> --package-lock-only --ignore-scripts --save-exact
            npm ci --ignore-scripts --audit=false
            npm ls --all --json   -> exit 0 AND parseable AND no `problems`
            target package AND version present in the tree
            ---- all of the above, or NO primary endpoint at all ----
            then, and only then, BOTH scanners re-scan
```

**A fix that cannot be installed is never recorded as remediated.** The install gate runs
before the re-scan, not after it.

## The arms

| Arm id | What answers |
|---|---|
| `npm_registry_audit_live` | `npm audit` 鈥?the configured registry's audit endpoint (GitHub Advisory Database behind it). Not called "the GHSA arm": that would overstate what is asked. |
| `osv_scanner_live` | `osv-scanner` **v2 (`scan` subcommand)**, with the fix bound to the **target advisory** and to the **event segment containing the installed version** 鈥?a range can hold several segments, and `last_affected` / `limit` / `GIT` never count as a fix. |
| `unified_frozen_model` | **Only** `H2_UNIFIED_RECOMMENDATIONS.json`. The pipeline computes nothing for this arm. |
| `nvd` | `not_evaluated_no_operational_scanner`, **excluded from every denominator**. No off-the-shelf NVD-only npm scanner exists 鈥?that is a limit of the tool ecosystem, not a measurement of NVD. |

Every arm's fix is re-scanned by **both** scanners. No tool grades its own homework.

## Before the first run

`pinned_tools.json` ships with `sha256: FILL_ME` for osv-scanner and **the workflow
refuses to start**. Fill it during the engineering pre-check:

```bash
curl -sSfL <url from pinned_tools.json> | sha256sum
# paste the digest into pinned_tools.json, commit, push
```

A census whose scanner version could differ between shards is not one experiment.

## Instantiating and running

```bash
git clone https://github.com/hfgjahgf/mock-vuln-npm-h2-pilot.git
cd mock-vuln-npm-h2-pilot
git rm -r --cached . && rm -rf .github scripts data      # keep history, replace tree
cp -a <thesis>/tools/h2_real_pipeline/. .   # -a and the trailing dot: `/*` skips .github
mkdir -p data
cp <thesis>/schemas/H2_REAL_ENVIRONMENTS.json       data/
cp <thesis>/schemas/H2_UNIFIED_RECOMMENDATIONS.json data/
# H2_R36_PREDICTION_SIDECAR.json must NOT be copied - it never enters this repo.
git add -A && git commit -m 'R37 live census kit' && git push

# engineering pre-check: two shards, ten environments each, results discarded
gh workflow run census.yml -f shard_count=200 -f shards='[0,1]' -f limit=10

# full census, once the pre-check confirms the parsers
gh workflow run census.yml -f shard_count=32 -f shards=all -f limit=0
```

Then download the artifacts and run the offline ingest back in the thesis repo.

## Safety, and why it is shaped this way

- **`permissions: contents: read`, no secrets.** Nothing here needs a writable token, so
  a malicious package has nothing to exfiltrate.
- **`--ignore-scripts` everywhere.** Thousands of unfamiliar packages are resolved and
  installed; none of their lifecycle scripts run. Native modules that consequently cannot
  be verified are flagged, not silently passed.
- **No `osv-scanner` guided remediation.** It is documented as experimental and warns it
  may invoke the package manager's scripts. Fixes are applied by us with
  `--package-lock-only --ignore-scripts`.
- **No smoke import.** `require()` would execute third-party code, and would misfire on
  ESM-only, browser-only and CLI packages anyway (protocol 搂5.3).

## Reproducibility

- osv-scanner pinned by version **and** SHA-256, verified before install.
- Node pinned; npm and OSV database state recorded per run.
- **The raw stdout behind every `raw_sha256` is kept** (`raw-*.jsonl.gz`, uploaded with
  the shard) 鈥?a checksum with nothing to check is not provenance.
- **The `package-lock.json` and the `npm ls` tree behind every scan are kept too** 鈥?
  otherwise there is no way to say afterwards which tree was scanned.
- npm registry, runner image and the `semver` package version are recorded per run.
- The live databases change daily, so the run happens once and its outputs are frozen on
  return. Everything downstream of that is offline and byte-reproducible.

## Order of work (protocol 搂7 - do not reorder)

1. fix the runner 鈫?2. **engineering pre-check, results discarded** 鈫?3. write and test
`ingest_h2_real_run.py` and `Test_h2_real_run.py` **against the pre-check output** 鈫?
4. freeze the runner/ingest/gate hashes 鈫?5. **one** full census.

> Running the full census first and writing the ingest afterwards means a missing field
> is discovered when that live-database instant has already passed.

## Testing the parsers before trusting them

```bash
python tests/Test_pipeline_parsers.py             # 22 checks
python tests/Test_pipeline_parsers.py --self-test  # 14 mutations
```

These run offline against fixtures. **If the real scanner output differs from the
fixtures, the fixtures and the parser change 鈥?never the criteria** (protocol 搂5.3b).

## R40 — the deployment run (`deployment.yml`)

**A second experiment in this repository, not a replacement for the census.**
`census.yml` ran R37 once and is evidence; it must not be edited. `deployment.yml` asks
a different question and has different endpoints.

The census carried a Unified arm computed in advance on a laptop and shipped as a file —
the model itself never reached a runner. R40 rebuilds it **on the runner** from seven
frozen inputs fetched by DOI and hash-verified one by one; 32 shards then load that
model and query it, and every recommendation is computed during the run.

Registered endpoints, and only these:

- **E1** — the rebuilt model matches `h1_seal_manifest.json`, section for section.
- **E2** — the chain run on the runner reproduces the committed ledger, scores,
  decisions and recommendations, byte for byte apart from a bounded set of
  line-ending-dependent digests, each accounted for individually.

**Install, scan and re-scan outcomes are archived and are NOT an endpoint.** The scanner
binary is pinned; its vulnerability database is not, and npm resolves against a registry
that has moved since the census ran on 2026-08-18. `h2_supported` stays `false` and is
not revisited.

### Assembling and running it

Do not copy the kit by hand — it is 32 files with two layouts in it: the pipeline files
land at this repository's root, everything else keeps its thesis-relative path. The
mapping lives in `schemas/R40_DEPLOYMENT_FREEZE.json` under
`kit_layout_thesis_to_public_repo`, and the copy is done by a script that hashes each
file after copying:

```bash
# from the thesis repository
python assemble_r40_kit.py --target <this repository>
git add -A && git commit -m 'R40 deployment kit' && git push
```

```bash
# engineering pre-check: one shard, ten environments, results DISCARDED
gh workflow run deployment.yml -f shard_count=200 -f shards='[0]' -f limit=10

# the counted run, once
gh workflow run deployment.yml -f shard_count=32 -f shards=all -f limit=0
```

Then, back in the thesis repository:

```bash
python ingest_r40_deployment.py --run <downloaded artifacts> --out r40_deployment_run.json
```

The ingest derives whether a return is a pre-check or the counted run **from the
workflow inputs the run recorded**, never from a flag passed to it. Four pre-checks were
needed before the counted one, and each found something: shards given the model but not
the inputs the chain opens; two artefacts that only rebuild on a matching line-ending
checkout; and a return that recorded no workflow inputs at all, so the rule deciding
whether it counted had nothing to read.

## What this cannot answer

Every fixture has one target instance at the top level, so **transitive pinning and
peer-dependency conflicts are out of scope**, and R36's `conflict = 0` is still not
tested against a real dependency tree. Protocol 搂3 states both costs.
