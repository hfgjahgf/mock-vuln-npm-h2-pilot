#!/usr/bin/env python3
"""compute_metrics.py — H2 stage v4 pilot metric computation.

Reads 3 arm outputs + GT tuples, computes per-arm metrics + attribution deltas.
Output: metrics_summary.json + status per arm.
"""

import argparse
import json
import re
import sys
from pathlib import Path


SEMVER_LIKE_RE = re.compile(r'^\d+(\.\d+){1,3}([-+]\S+)?$')
COMMIT_SHA_RE = re.compile(r'^[0-9a-f]{7,40}$', re.IGNORECASE)


def normalize_version(v):
    if v is None:
        return None
    return str(v).strip().lstrip('vV').strip().lower()


def classify_tier(fv):
    if fv is None or fv == '':
        return None
    s = str(fv).strip()
    if SEMVER_LIKE_RE.match(s.lstrip('vV')):
        return 'A'
    if COMMIT_SHA_RE.match(s):
        return 'P'
    if s.lower().startswith('cpe:'):
        return 'N'
    return 'N'


def parse_grype_output(path):
    """Parse Grype JSON — returns list of {primary_id, aliases[], cve_ids[], package, fix_versions[], namespace}.

    Grype primary IDs for npm packages are GHSA-* (from github:language:javascript namespace).
    CVE IDs are in relatedVulnerabilities[].id — we collect both primary + aliases.
    """
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    entries = []
    for m in data.get('matches') or []:
        v = m.get('vulnerability') or {}
        artifact = m.get('artifact') or {}
        primary = v.get('id')
        related = v.get('relatedVulnerabilities') or []
        # All IDs — primary + related (for cross-ID matching)
        all_ids = {primary}
        cve_ids = set()
        for rv in related:
            rid = rv.get('id') or ''
            if rid:
                all_ids.add(rid)
                if rid.startswith('CVE-'):
                    cve_ids.add(rid)
        if primary and primary.startswith('CVE-'):
            cve_ids.add(primary)

        fix = v.get('fix') or {}
        fix_versions = fix.get('versions') or []

        entries.append({
            'primary_id': primary,
            'all_ids': sorted(all_ids),
            'cve_ids': sorted(cve_ids),
            'package': artifact.get('name'),
            'version': artifact.get('version'),
            'fix_versions': fix_versions,
            'namespace': v.get('namespace'),
        })
    return entries


def parse_canonical_output(path):
    """Parse canonical-lookup output — has sources labels + all_ids alias chain."""
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    entries = []
    for m in data.get('matches') or []:
        primary = m.get('primary_id') or m.get('cve_id')
        all_ids = m.get('all_ids') or ([primary] if primary else [])
        cve_ids = [i for i in all_ids if i and i.startswith('CVE-')]
        entries.append({
            'primary_id': primary,
            'all_ids': all_ids,
            'cve_ids': cve_ids,
            'package': m.get('package'),
            'version': m.get('version'),
            'fix_versions': m.get('fix_versions') or [],
            'namespace': m.get('namespace'),
            'sources': m.get('sources') or [],
        })
    return entries


def compute_arm_metrics(entries, gt_tuples):
    """For each GT tuple, check coverage + actionability + traceability + tier composition."""
    per_tuple = []
    for gt in gt_tuples:
        target_cve = gt['cve_id']
        target_pkg = gt['package']
        gt_fixes = {normalize_version(v) for v in gt.get('reference_fix_versions', [])}
        gt_fixes.discard(None)

        # Filter entries matching target_cve × target_pkg
        # Match by CVE ID appearing in ANY of the entry's IDs (primary + related aliases)
        matched = []
        for e in entries:
            e_pkg = (e.get('package') or '').lower()
            all_ids = e.get('all_ids') or ([e.get('primary_id')] if e.get('primary_id') else [])
            if target_cve in all_ids and target_pkg.lower() == e_pkg:
                matched.append(e)

        # Compute tier
        tier_counts = {'A': 0, 'P': 0, 'N': 0}
        output_versions = set()
        has_sources_labels = False
        for e in matched:
            for fv in (e.get('fix_versions') or []):
                nv = normalize_version(fv)
                if nv:
                    output_versions.add(nv)
                t = classify_tier(fv)
                if t:
                    tier_counts[t] += 1
            if e.get('sources'):
                has_sources_labels = True

        coverage_hit = bool(output_versions & gt_fixes)
        actionability = tier_counts['A'] > 0

        per_tuple.append({
            'cve_id': target_cve,
            'package': target_pkg,
            'stratum': gt.get('stratum'),
            'coverage_hit': int(coverage_hit),
            'actionability': int(actionability),
            'traceability': int(has_sources_labels),
            'tier_A': tier_counts['A'],
            'tier_P': tier_counts['P'],
            'tier_N': tier_counts['N'],
            'output_versions': sorted(output_versions),
        })

    # Aggregate
    n = len(per_tuple)
    agg = {
        'n_tuples': n,
        'coverage_hit': sum(t['coverage_hit'] for t in per_tuple),
        'actionability': sum(t['actionability'] for t in per_tuple),
        'traceability': sum(t['traceability'] for t in per_tuple),
        'tier_A': sum(t['tier_A'] for t in per_tuple),
        'tier_P': sum(t['tier_P'] for t in per_tuple),
        'tier_N': sum(t['tier_N'] for t in per_tuple),
        'per_tuple': per_tuple,
    }
    return agg


def load_grype_db_metadata(path='grype_db_metadata.json'):
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nvd_only', required=True)
    ap.add_argument('--scanner_native', required=True)
    ap.add_argument('--canonical', required=True)
    ap.add_argument('--gt', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()

    # Load GT tuples
    gt_tuples = json.loads(Path(args.gt).read_text(encoding='utf-8'))
    print(f'Loaded {len(gt_tuples)} GT tuples')

    # Parse arm outputs
    arm_entries = {
        'nvd_only': parse_grype_output(args.nvd_only),
        'scanner_native': parse_grype_output(args.scanner_native),
        'canonical': parse_canonical_output(args.canonical),
    }
    for arm, e in arm_entries.items():
        print(f'  {arm}: {len(e)} entries')

    # Compute metrics per arm
    arm_metrics = {arm: compute_arm_metrics(entries, gt_tuples)
                   for arm, entries in arm_entries.items()}

    # Attribution deltas
    def d(a1, a2, key):
        return arm_metrics[a1][key] - arm_metrics[a2][key]

    delta_scanner = {
        'coverage': d('scanner_native', 'nvd_only', 'coverage_hit'),
        'actionability': d('scanner_native', 'nvd_only', 'actionability'),
    }
    delta_canonical = {
        'coverage': d('canonical', 'scanner_native', 'coverage_hit'),
        'actionability': d('canonical', 'scanner_native', 'actionability'),
        'traceability': d('canonical', 'scanner_native', 'traceability'),
    }

    # Canonical is the enforcing gate — it passes if canonical FN_strict = 0 (all tuples have tier-A)
    all_canon_tier_a = all(t['tier_A'] > 0 for t in arm_metrics['canonical']['per_tuple'])

    db_meta = load_grype_db_metadata()

    summary = {
        'nvd_only': {
            **arm_metrics['nvd_only'],
            'status': 'success' if arm_metrics['nvd_only']['coverage_hit'] > 0 else 'failure',
        },
        'scanner_native': {
            **arm_metrics['scanner_native'],
            'status': 'success' if arm_metrics['scanner_native']['coverage_hit'] > 0 else 'failure',
        },
        'canonical': {
            **arm_metrics['canonical'],
            'status': 'success' if all_canon_tier_a else 'failure',
        },
        'delta_scanner': delta_scanner,
        'delta_canonical': delta_canonical,
        'grype_db_built': (db_meta or {}).get('built', 'unknown'),
        'grype_db_checksum': (db_meta or {}).get('checksum', 'unknown'),
    }

    Path(args.output).write_text(json.dumps(summary, indent=2), encoding='utf-8')

    # Print summary table
    print('\n' + '=' * 76)
    print('Attribution decomposition summary')
    print('=' * 76)
    print(f'{"Arm":<20s} {"Cov":>4s} {"Act":>4s} {"Trace":>6s} {"A/P/N":>10s} {"Status":>10s}')
    print('-' * 76)
    for arm in ['nvd_only', 'scanner_native', 'canonical']:
        a = summary[arm]
        tier = f'{a["tier_A"]}/{a["tier_P"]}/{a["tier_N"]}'
        print(f'{arm:<20s} {a["coverage_hit"]:>4d} {a["actionability"]:>4d} '
              f'{a["traceability"]:>6d} {tier:>10s} {a["status"]:>10s}')

    print(f'\nΔ_scanner_aggregation: coverage={delta_scanner["coverage"]:+d} '
          f'actionability={delta_scanner["actionability"]:+d}')
    print(f'Δ_canonical_algorithm: coverage={delta_canonical["coverage"]:+d} '
          f'actionability={delta_canonical["actionability"]:+d} '
          f'traceability={delta_canonical["traceability"]:+d}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
