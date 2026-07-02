#!/usr/bin/env python3
"""direct_lookup.py — Independent detection arms (nvd_direct + canonical_direct).

Not downstream of any scanner. Given a list of (pkg, version) tuples from lockfile
+ our pilot GT tuples, query local NVD / canonical snapshot to detect vulnerabilities.

Two modes:
  --mode nvd:       lookup in nvd_data/ (raw NVD CVE responses)
  --mode canonical: lookup in canonical_data/unified_canonical.json

Output: same schema as canonical_lookup.py so compute_metrics can parse both."""

import argparse
import json
import re
import sys
from pathlib import Path


SEMVER_LIKE_RE = re.compile(r'^\d+(\.\d+){1,3}([-+]\S+)?$')


def normalize_version(v):
    if v is None:
        return None
    return str(v).strip().lstrip('vV').strip().lower()


def _pkg_matches(target_pkg, candidate):
    """Loose match: exact OR substring OR CPE-style vendor:product match."""
    if not candidate or not target_pkg:
        return False
    t = target_pkg.lower()
    c = candidate.lower()
    if t == c:
        return True
    if t in c or c in t:
        return True
    return False


def lookup_canonical(pilot_tuples, canonical_snapshot):
    """For each pilot tuple, find matching entry in canonical.
    Returns Grype-schema output (matches list)."""
    # Index canonical by CVE
    idx = {}
    for r in canonical_snapshot:
        cve = r.get('cve_id')
        if cve:
            idx[cve] = r

    matches = []
    for t in pilot_tuples:
        cve = t['cve_id']
        pkg = t['package']
        rec = idx.get(cve)
        if not rec:
            continue

        # Search affected entries matching pkg
        for a in (rec.get('affected') or []):
            a_pkg = a.get('package')
            if not _pkg_matches(pkg, a_pkg):
                continue

            fv = a.get('fixed_version')
            fix_versions = []
            if fv:
                fix_versions.append(fv)

            # canonical sources labels — the traceability contribution
            sources = list(a.get('sources') or [])

            # Collect alias IDs from canonical record's ids field
            ids = rec.get('ids') or {}
            all_ids = [cve]
            for g in (ids.get('ghsa_id') or []):
                if isinstance(g, dict) and g.get('value'):
                    all_ids.append(g['value'])
            for al in (ids.get('aliases') or []):
                if al not in all_ids:
                    all_ids.append(al)

            matches.append({
                'cve_id': cve,
                'primary_id': cve,
                'all_ids': all_ids,
                'package': pkg,  # use pilot pkg name for direct matching
                'version': t.get('vulnerable_version'),
                'fix_versions': fix_versions,
                'namespace': 'canonical:direct',
                'sources': sources,
            })

    return {'matches': matches, 'total': len(matches)}


def lookup_nvd(pilot_tuples, nvd_dir):
    """For each pilot tuple, load NVD raw for that CVE, extract fix version."""
    matches = []
    for t in pilot_tuples:
        cve = t['cve_id']
        pkg = t['package']
        nvd_path = Path(nvd_dir) / f'{cve}.json'
        if not nvd_path.exists():
            continue
        raw = json.loads(nvd_path.read_text(encoding='utf-8'))

        # NVD JSON has vulnerabilities[0].cve.configurations for CPE matching
        # and vulnerabilities[0].cve.metrics for CVSS. For fix info:
        # Look for configurations with cpe_match entries containing versionEndExcluding
        vulns = raw.get('vulnerabilities') or [raw] if 'cve' in raw else []
        if not vulns and raw.get('cve'):
            vulns = [raw]

        for v in vulns:
            cve_obj = v.get('cve') or v
            fix_versions = []
            found_pkg = False

            for cfg in (cve_obj.get('configurations') or []):
                for node in (cfg.get('nodes') or []):
                    for cm in (node.get('cpeMatch') or []):
                        cpe = cm.get('criteria', '')
                        # CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                        parts = cpe.split(':')
                        if len(parts) >= 5:
                            product = parts[4]
                            if _pkg_matches(pkg, product):
                                found_pkg = True
                                ve = cm.get('versionEndExcluding')
                                if ve:
                                    fix_versions.append(ve)

            if found_pkg:
                # dedup
                fix_versions = list(dict.fromkeys(fix_versions))
                matches.append({
                    'cve_id': cve,
                    'primary_id': cve,
                    'all_ids': [cve],
                    'package': pkg,
                    'version': t.get('vulnerable_version'),
                    'fix_versions': fix_versions,
                    'namespace': 'nvd:direct',
                    'sources': ['nvd'] if fix_versions else [],
                })
                break

    return {'matches': matches, 'total': len(matches)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', required=True, choices=['nvd', 'canonical'])
    ap.add_argument('--pilot-tuples', required=True)
    ap.add_argument('--nvd-dir', default='nvd_data')
    ap.add_argument('--canonical-snapshot', default='canonical_data/unified_canonical.json')
    ap.add_argument('--output', required=True)
    args = ap.parse_args()

    tuples = json.loads(Path(args.pilot_tuples).read_text(encoding='utf-8'))

    if args.mode == 'nvd':
        result = lookup_nvd(tuples, args.nvd_dir)
    else:
        snap = json.loads(Path(args.canonical_snapshot).read_text(encoding='utf-8'))
        result = lookup_canonical(tuples, snap)

    Path(args.output).write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f'{args.mode}_direct: {result["total"]} matches → {args.output}')


if __name__ == '__main__':
    sys.exit(main())
