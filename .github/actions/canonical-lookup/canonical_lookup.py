#!/usr/bin/env python3
"""canonical-lookup composite action entrypoint.

Takes Grype JSON output + canonical snapshot → outputs canonical-normalized JSON:
  - dedup (by CVE ID)
  - normalize fix versions (semver)
  - attach sources[] labels (from canonical snapshot)
"""

import argparse
import json
import sys
from pathlib import Path


def normalize_version(v):
    if v is None:
        return None
    return str(v).strip().lstrip('vV').strip().lower()


def load_json(p):
    return json.loads(Path(p).read_text(encoding='utf-8'))


def build_canonical_index(canonical_snapshot):
    """Build {vuln_id: {package: sources_labels}} index for label lookup.

    Keys include CVE_id AND all its alias IDs (GHSA-*, aliases) so we can lookup
    by GHSA-* IDs (which is what Grype outputs for npm packages).
    """
    idx = {}
    for r in canonical_snapshot:
        cve = r.get('cve_id')
        if not cve:
            continue
        # Collect all IDs for this record (CVE + GHSA + aliases)
        keys = {cve}
        ids = r.get('ids') or {}
        for g in (ids.get('ghsa_id') or []):
            if isinstance(g, dict):
                v = g.get('value')
                if v:
                    keys.add(v)
        for al in (ids.get('aliases') or []):
            keys.add(al)

        for a in (r.get('affected') or []):
            pkg = a.get('package')
            if not pkg:
                continue
            sources_here = list(a.get('sources') or [])
            for key in keys:
                idx.setdefault(key, {}).setdefault(pkg, [])
                for s in sources_here:
                    if s not in idx[key][pkg]:
                        idx[key][pkg].append(s)
    return idx


def process(grype_output, canonical_index):
    """Normalize + dedup + attach sources labels.

    Preserves all IDs (primary + related aliases) so downstream can match by CVE
    even when Grype's primary ID is GHSA-*.
    Also looks up sources in canonical snapshot by ANY of the entry's IDs.
    """
    out_matches = []
    seen = set()
    for m in grype_output.get('matches') or []:
        v = m.get('vulnerability') or {}
        primary = v.get('id')
        artifact = m.get('artifact') or {}
        pkg = artifact.get('name')

        # Collect all IDs (primary + related for CVE-alias linking)
        related = v.get('relatedVulnerabilities') or []
        all_ids = [primary] if primary else []
        for rv in related:
            rid = rv.get('id')
            if rid and rid not in all_ids:
                all_ids.append(rid)

        # Dedup by (primary_id, package)
        key = (primary, pkg)
        if key in seen:
            continue
        seen.add(key)

        # Normalize fix versions
        fix = v.get('fix') or {}
        norm_versions = [normalize_version(fv) for fv in (fix.get('versions') or [])]
        norm_versions = [x for x in norm_versions if x is not None]

        # Attach sources labels: look up ANY of the IDs in canonical index
        sources = []
        for candidate_id in all_ids:
            for s in canonical_index.get(candidate_id, {}).get(pkg, []):
                if s not in sources:
                    sources.append(s)

        out_matches.append({
            'cve_id': primary,          # backward-compat field
            'primary_id': primary,
            'all_ids': all_ids,          # preserve alias chain for downstream matching
            'package': pkg,
            'version': artifact.get('version'),
            'fix_versions': norm_versions,
            'namespace': v.get('namespace'),
            'sources': sources,          # <-- canonical's traceability contribution
        })

    return {'matches': out_matches, 'total': len(out_matches)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--grype-input', required=True)
    ap.add_argument('--canonical-snapshot', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()

    grype = load_json(args.grype_input)
    canonical = load_json(args.canonical_snapshot)
    idx = build_canonical_index(canonical)
    result = process(grype, idx)

    Path(args.output).write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f'canonical-lookup: {result["total"]} matches processed → {args.output}')


if __name__ == '__main__':
    sys.exit(main())
