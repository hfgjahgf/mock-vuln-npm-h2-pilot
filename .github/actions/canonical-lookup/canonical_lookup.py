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
    """Build {cve_id: {package: sources_labels}} index for label lookup."""
    idx = {}
    for r in canonical_snapshot:
        cve = r.get('cve_id')
        if not cve:
            continue
        for a in (r.get('affected') or []):
            pkg = a.get('package')
            if not pkg:
                continue
            idx.setdefault(cve, {}).setdefault(pkg, [])
            for s in (a.get('sources') or []):
                if s not in idx[cve][pkg]:
                    idx[cve][pkg].append(s)
    return idx


def process(grype_output, canonical_index):
    """Normalize + dedup + attach sources labels."""
    out_matches = []
    seen = set()
    for m in grype_output.get('matches') or []:
        v = m.get('vulnerability') or {}
        vid = v.get('id')
        artifact = m.get('artifact') or {}
        pkg = artifact.get('name')

        # Dedup by (CVE, package)
        key = (vid, pkg)
        if key in seen:
            continue
        seen.add(key)

        # Normalize fix versions
        fix = v.get('fix') or {}
        norm_versions = [normalize_version(fv) for fv in (fix.get('versions') or [])]
        norm_versions = [v for v in norm_versions if v is not None]

        # Attach sources labels from canonical snapshot
        sources = canonical_index.get(vid, {}).get(pkg, [])

        out_matches.append({
            'cve_id': vid,
            'package': pkg,
            'version': artifact.get('version'),
            'fix_versions': norm_versions,
            'namespace': v.get('namespace'),
            'sources': sources,  # <-- canonical's traceability contribution
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
