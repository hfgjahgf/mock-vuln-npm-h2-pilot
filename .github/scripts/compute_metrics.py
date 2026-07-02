#!/usr/bin/env python3
"""compute_metrics.py — v4' 4-arm × 3-ecosystem attribution decomposition.

4 arms:
  A1 nvd_direct              — independent detection (NVD raw lookup)
  A2 grype_native            — real scanner (Grype output)
  A3 canonical_enrichment    — Grype downstream (bounded by A2)
  A4 canonical_direct        — independent detection (canonical snapshot lookup)

Key deltas:
  Δ_grype_aggregation      = A2 - A1  (scanner DB aggregation benefit)
  Δ_traceability_only      = A3 - A2  (enrichment layer value; expected ≤ 0 on coverage, ≥ 0 on trace)
  Δ_architecture           = A4 - A3  (independent vs enrichment insertion architecture)
  Δ_gap_recovery           = A4 - A2  (canonical direct vs scanner; scanner blind spots)
"""

import argparse
import json
import re
import sys
from collections import defaultdict
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


def build_cve_alias_map(canonical_snapshot_path):
    if not Path(canonical_snapshot_path).exists():
        return {}
    snap = json.loads(Path(canonical_snapshot_path).read_text(encoding='utf-8'))
    alias_map = {}
    for r in snap:
        cve = r.get('cve_id')
        if not cve:
            continue
        ids = r.get('ids') or {}
        aliases = set(ids.get('aliases') or [])
        for g in (ids.get('ghsa_id') or []):
            if isinstance(g, dict):
                v = g.get('value')
                if v:
                    aliases.add(v)
        aliases.add(cve)
        alias_map[cve] = aliases
    return alias_map


def parse_grype_output(path):
    """Real Grype JSON."""
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    entries = []
    for m in data.get('matches') or []:
        v = m.get('vulnerability') or {}
        artifact = m.get('artifact') or {}
        primary = v.get('id')
        related = v.get('relatedVulnerabilities') or []
        all_ids = {primary} if primary else set()
        for rv in related:
            rid = rv.get('id') or ''
            if rid:
                all_ids.add(rid)

        fix = v.get('fix') or {}
        fix_versions = fix.get('versions') or []

        entries.append({
            'primary_id': primary,
            'all_ids': sorted(all_ids),
            'package': artifact.get('name'),
            'fix_versions': fix_versions,
            'namespace': v.get('namespace'),
            'sources': [],  # Grype native has no structured sources
        })
    return entries


def parse_direct_or_canonical_output(path):
    """Our direct_lookup / canonical_lookup output (already schema-normalized)."""
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    entries = []
    for m in data.get('matches') or []:
        entries.append({
            'primary_id': m.get('primary_id') or m.get('cve_id'),
            'all_ids': m.get('all_ids') or [m.get('cve_id')],
            'package': m.get('package'),
            'fix_versions': m.get('fix_versions') or [],
            'namespace': m.get('namespace'),
            'sources': m.get('sources') or [],
        })
    return entries


def _pkg_match(target, candidate):
    if not candidate or not target:
        return False
    t = target.lower(); c = candidate.lower()
    return t == c or t in c or c in t


def compute_arm_metrics(entries, gt_tuples, alias_map):
    per_tuple = []
    for gt in gt_tuples:
        target_cve = gt['cve_id']
        target_pkg = gt['package']
        eco = gt.get('ecosystem', '?')
        alias_set = alias_map.get(target_cve, {target_cve})
        gt_fixes = {normalize_version(v) for v in gt.get('reference_fix_versions', [])}
        gt_fixes.discard(None)

        # Match entries where any ID in alias_set + pkg matches target
        matched = []
        for e in entries:
            e_ids = set(e.get('all_ids') or [e.get('primary_id')]) if e.get('primary_id') else set()
            if e_ids & alias_set and _pkg_match(target_pkg, e.get('package')):
                matched.append(e)

        tier_counts = {'A': 0, 'P': 0, 'N': 0}
        output_versions = set()
        has_sources = False
        for e in matched:
            for fv in (e.get('fix_versions') or []):
                nv = normalize_version(fv)
                if nv:
                    output_versions.add(nv)
                t = classify_tier(fv)
                if t:
                    tier_counts[t] += 1
            if e.get('sources'):
                has_sources = True

        coverage_hit = bool(output_versions & gt_fixes)
        actionability = tier_counts['A'] > 0

        per_tuple.append({
            'cve_id': target_cve, 'package': target_pkg, 'ecosystem': eco,
            'coverage_hit': int(coverage_hit),
            'actionability': int(actionability),
            'traceability': int(has_sources),
            'tier_A': tier_counts['A'],
            'tier_P': tier_counts['P'],
            'tier_N': tier_counts['N'],
            'output_versions': sorted(output_versions),
        })

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
    # Per-ecosystem breakdown
    per_eco = defaultdict(lambda: {'n': 0, 'coverage_hit': 0, 'actionability': 0, 'traceability': 0})
    for t in per_tuple:
        e = per_eco[t['ecosystem']]
        e['n'] += 1
        e['coverage_hit'] += t['coverage_hit']
        e['actionability'] += t['actionability']
        e['traceability'] += t['traceability']
    agg['per_ecosystem'] = dict(per_eco)
    return agg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--a1_nvd_direct', required=True)
    ap.add_argument('--a2_grype_native', required=True)
    ap.add_argument('--a3_canonical_enrichment', required=True)
    ap.add_argument('--a4_canonical_direct', required=True)
    ap.add_argument('--gt', required=True)
    ap.add_argument('--canonical-snapshot', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()

    gt_tuples = json.loads(Path(args.gt).read_text(encoding='utf-8'))
    print(f'Loaded {len(gt_tuples)} GT tuples')

    alias_map = build_cve_alias_map(args.canonical_snapshot)
    print(f'CVE alias map: {len(alias_map)} entries')

    arm_entries = {
        'a1_nvd_direct': parse_direct_or_canonical_output(args.a1_nvd_direct),
        'a2_grype_native': parse_grype_output(args.a2_grype_native),
        'a3_canonical_enrichment': parse_direct_or_canonical_output(args.a3_canonical_enrichment),
        'a4_canonical_direct': parse_direct_or_canonical_output(args.a4_canonical_direct),
    }
    for arm, ents in arm_entries.items():
        print(f'  {arm}: {len(ents)} entries')

    arm_metrics = {arm: compute_arm_metrics(entries, gt_tuples, alias_map)
                   for arm, entries in arm_entries.items()}

    def d(a1, a2, key):
        return arm_metrics[a1][key] - arm_metrics[a2][key]

    summary = {
        'a1_nvd_direct': arm_metrics['a1_nvd_direct'],
        'a2_grype_native': arm_metrics['a2_grype_native'],
        'a3_canonical_enrichment': arm_metrics['a3_canonical_enrichment'],
        'a4_canonical_direct': arm_metrics['a4_canonical_direct'],
        'delta_grype_aggregation': {  # A2 - A1
            'coverage': d('a2_grype_native', 'a1_nvd_direct', 'coverage_hit'),
            'actionability': d('a2_grype_native', 'a1_nvd_direct', 'actionability'),
        },
        'delta_traceability_only': {  # A3 - A2
            'coverage': d('a3_canonical_enrichment', 'a2_grype_native', 'coverage_hit'),
            'actionability': d('a3_canonical_enrichment', 'a2_grype_native', 'actionability'),
            'traceability': d('a3_canonical_enrichment', 'a2_grype_native', 'traceability'),
        },
        'delta_architecture': {  # A4 - A3  KEY FINDING
            'coverage': d('a4_canonical_direct', 'a3_canonical_enrichment', 'coverage_hit'),
            'actionability': d('a4_canonical_direct', 'a3_canonical_enrichment', 'actionability'),
            'traceability': d('a4_canonical_direct', 'a3_canonical_enrichment', 'traceability'),
        },
        'delta_gap_recovery': {  # A4 - A2  KEY FINDING
            'coverage': d('a4_canonical_direct', 'a2_grype_native', 'coverage_hit'),
            'actionability': d('a4_canonical_direct', 'a2_grype_native', 'actionability'),
            'traceability': d('a4_canonical_direct', 'a2_grype_native', 'traceability'),
        },
    }

    Path(args.output).write_text(json.dumps(summary, indent=2), encoding='utf-8')

    # Print summary
    print('\n' + '=' * 90)
    print(f'{"Arm":<24s} {"n":>3s} {"Cov":>5s} {"Act":>5s} {"Trace":>6s} {"A/P/N":>10s}')
    print('-' * 90)
    for arm in ['a1_nvd_direct', 'a2_grype_native', 'a3_canonical_enrichment', 'a4_canonical_direct']:
        a = summary[arm]
        tier = f'{a["tier_A"]}/{a["tier_P"]}/{a["tier_N"]}'
        print(f'{arm:<24s} {a["n_tuples"]:>3d} {a["coverage_hit"]:>5d} '
              f'{a["actionability"]:>5d} {a["traceability"]:>6d} {tier:>10s}')

    print('\n=== Attribution deltas ===')
    print(f'Δ_grype_aggregation (A2-A1): {summary["delta_grype_aggregation"]}')
    print(f'Δ_traceability_only (A3-A2): {summary["delta_traceability_only"]}')
    print(f'Δ_architecture      (A4-A3): {summary["delta_architecture"]}   ← KEY FINDING (indep vs enrichment)')
    print(f'Δ_gap_recovery      (A4-A2): {summary["delta_gap_recovery"]}   ← KEY FINDING (canonical direct vs scanner)')

    print('\n=== Per-ecosystem breakdown (arm × cov) ===')
    ecos = ['npm', 'pip', 'maven']
    print(f'  {"":<24s}  ' + '  '.join(f'{e:>10s}' for e in ecos))
    for arm in ['a1_nvd_direct', 'a2_grype_native', 'a3_canonical_enrichment', 'a4_canonical_direct']:
        row = f'  {arm:<24s}  '
        for e in ecos:
            pe = summary[arm].get('per_ecosystem', {}).get(e, {'n': 0, 'coverage_hit': 0})
            row += f'{pe["coverage_hit"]:>3d}/{pe["n"]:<3d}       '
        print(row)

    return 0


if __name__ == '__main__':
    sys.exit(main())
