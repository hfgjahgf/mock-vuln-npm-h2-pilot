"""Relation-aware query over unified_model_v3.

R25 PRESERVED the relations; it did not let anyone ASK with them. This module is the
query view, and its whole job is to return three things at once without letting them
mix:

  direct_assertions        assertions attributable to THIS entity. These are what
                           H1 completeness and H2 may read - and only the ones whose
                           `contributes_completeness_field` is true carry a usable
                           value.
  related_context          records reached through `upstream` / `related`, with their
                           assertions. Shown, never counted. A fix that belongs to an
                           upstream vulnerability is context for a reader and would be
                           a fabricated field if it were folded in.
  record_level_assertions  advisory-level and ambiguous rows, attached to the record
                           where they were made and to no CVE.

WHY upstream AND related ARE ONLY CONTEXT

  Per the OSV schema (https://ossf.github.io/osv-schema/): `aliases` means the same
  vulnerability, `upstream` means an upstream vulnerability, `related` means merely
  related. Only the first is an identity claim, and even that one is honoured solely
  when the alias is a CVE the record declares as its own. 7,810 of the 9,528
  no-direct-CVE-identity records name a CVE in upstream or related - which is exactly
  why they are called "no DIRECT CVE identity" and not "no CVE".

  python query_unified_v3.py CVE-2026-12345
  python query_unified_v3.py native:ghsa:GHSA-xxxx-xxxx-xxxx
  python query_unified_v3.py CVE-2026-12345 --json
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from identity_extract import iter_jsonl_gz

ROOT = Path(__file__).resolve().parent
MODEL = ROOT / 'output' / 'unified_model_v3'
ASSERTION_SECTIONS = ('assertions_severity', 'assertions_cwe',
                      'assertions_affected', 'assertions_generic')
CONTEXT_RELATIONS = ('upstream', 'related')


class Model:
    """The sections a query needs, loaded once."""

    def __init__(self, model_dir=MODEL):
        self.dir = model_dir
        self.entities = {e['entity_id']: e
                         for e in iter_jsonl_gz(model_dir / 'entities.jsonl.gz')}
        self.by_identifier = {e['preferred_identifier']: eid
                              for eid, e in self.entities.items()}
        self.records = {r['record_ref']: r for r in
                        iter_jsonl_gz(model_dir / 'source_records.jsonl.gz')}
        self.records_of = defaultdict(list)
        self.entities_of_record = defaultdict(list)
        for link in iter_jsonl_gz(model_dir / 'entity_record_links.jsonl.gz'):
            self.records_of[link['entity_id']].append(link['record_ref'])
            self.entities_of_record[link['record_ref']].append(link['entity_id'])
        self.relations_of = defaultdict(list)
        self.records_naming = defaultdict(list)
        for rel in iter_jsonl_gz(model_dir / 'relations.jsonl.gz'):
            self.relations_of[rel['record_ref']].append(rel)
            self.records_naming[rel['target']].append(rel)
        self.assertions_of_record = defaultdict(list)
        for name in ASSERTION_SECTIONS:
            for row in iter_jsonl_gz(model_dir / f'{name}.jsonl.gz'):
                self.assertions_of_record[row['record_ref']].append(
                    {'section': name, **row})
        self.coverage = {c['entity_id']: c for c in
                         iter_jsonl_gz(model_dir / 'coverage_map.jsonl.gz')}
        self.matrix = {m['entity_id']: m for m in
                       iter_jsonl_gz(model_dir / 'completeness_matrix.jsonl.gz')}

    def resolve(self, key):
        """Accepts an entity_id, a CVE, or a native:<source>:<id> key."""
        if key in self.entities:
            return key
        return self.by_identifier.get(key)


def query(model, key):
    eid = model.resolve(key)
    if eid is None:
        return {'query': key, 'found': False,
                'hint': 'give a CVE id, a native:<source>:<native_id> key, '
                        'or an entity_id'}
    entity = model.entities[eid]
    refs = sorted(set(model.records_of[eid]))

    direct, record_level = [], []
    for ref in refs:
        for a in model.assertions_of_record[ref]:
            if a['entity_id'] == eid:
                direct.append(a)
            elif a['entity_id'] is None:
                record_level.append(a)

    # context: what these records point AT, and what points at them. Neither
    # direction is identity; both are shown so a reader can follow the trail.
    context_refs, context_edges = set(), []
    for ref in refs:
        for rel in model.relations_of[ref]:
            if rel['relation_type'] not in CONTEXT_RELATIONS:
                continue
            context_edges.append({**rel, 'direction': 'outgoing'})
            target_eid = model.by_identifier.get(rel['target'])
            for r2 in model.records_of.get(target_eid, []):
                context_refs.add(r2)
    for rel in model.records_naming.get(entity['preferred_identifier'], []):
        if rel['relation_type'] in CONTEXT_RELATIONS:
            context_edges.append({**rel, 'direction': 'incoming'})
            context_refs.add(rel['record_ref'])
    context_refs -= set(refs)

    related_context = []
    for ref in sorted(context_refs):
        rec = model.records.get(ref)
        if rec is None:
            continue
        related_context.append({
            'record_ref': ref, 'source': rec['source'],
            'declared_cves': rec['declared_cves'],
            'assertion_kinds': sorted({a['assertion_kind']
                                       for a in model.assertions_of_record[ref]}),
            'counts_toward_this_entity': False})

    cov = model.coverage.get(eid, {})
    return {
        'query': key, 'found': True,
        'entity': {k: entity[k] for k in
                   ('entity_id', 'preferred_identifier', 'entity_kind', 'stratum',
                    'record_count', 'source_count', 'derived_severity_max_by_scale',
                    'actionable_remediation')},
        'direct_records': [{'record_ref': r, 'source': model.records[r]['source'],
                            'native_id': model.records[r]['native_id']}
                           for r in refs if r in model.records],
        'direct_assertions': {
            'total': len(direct),
            'contributing_completeness_fields': sum(
                1 for a in direct if a['contributes_completeness_field']),
            'fields_supplied': sorted({f for a in direct
                                       if a['contributes_completeness_field']
                                       for f in a['usable_fields']}),
            'by_kind': {k: sum(1 for a in direct if a['assertion_kind'] == k)
                        for k in sorted({a['assertion_kind'] for a in direct})},
            'rows': direct,
        },
        'record_level_assertions': {
            'total': len(record_level),
            'note': 'advisory-level or ambiguous; attached to no CVE',
            'rows': record_level,
        },
        'related_context': {
            'records': related_context,
            'edges': context_edges,
            'note': ('reached through upstream/related. Displayed for traceability '
                     'and NEVER counted toward this entity: per the OSV schema '
                     'upstream is an upstream vulnerability and related is merely '
                     'related, so neither states that this is the same thing'),
        },
        'coverage': {k: cov.get(k) for k in
                     ('direct_sources', 'back_query_sources',
                      'back_query_only_sources', 'back_query_status',
                      'npm_actionable')},
        'completeness_matrix': model.matrix.get(eid),
    }


def summarise(q):
    if not q['found']:
        print(f"not found: {q['query']}\n  {q['hint']}")
        return 1
    e, d = q['entity'], q['direct_assertions']
    print(f"{e['preferred_identifier']}  [{e['entity_kind']} / {e['stratum']}]  "
          f"{e['entity_id']}")
    print(f"  direct records   : {len(q['direct_records'])} "
          f"{[r['record_ref'] for r in q['direct_records']][:6]}")
    print(f"  direct assertions: {d['total']} ({d['contributing_completeness_fields']}"
          f" contribute) by kind {d['by_kind']}")
    print(f"  fields supplied  : {d['fields_supplied']}")
    print(f"  record-level     : {q['record_level_assertions']['total']} "
          f"(counted for no CVE)")
    rc = q['related_context']
    print(f"  related context  : {len(rc['records'])} records via "
          f"{len(rc['edges'])} upstream/related edges - shown, never counted")
    for r in rc['records'][:5]:
        print(f"      {r['record_ref']:42s} {r['assertion_kinds']}")
    print(f"  coverage         : direct {q['coverage']['direct_sources']} | "
          f"back-query only {q['coverage']['back_query_only_sources']}")
    m = q['completeness_matrix']
    if m:
        for s in ('nvd', 'ghsa', 'osv'):
            v = m['by_source'][s]
            have = ([f for f, x in v['fields'].items() if x]
                    if v['observation_status'] == 'direct_record' else '-')
            print(f"      {s:5s} {v['observation_status']:20s} {have}")
        print(f"      unified   {[f for f, x in m['unified']['fields'].items() if x]}")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('key', help='CVE id, native:<source>:<native_id>, or entity_id')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--model-dir', default=str(MODEL))
    args = ap.parse_args()
    d = Path(args.model_dir)
    if not (d / 'entities.jsonl.gz').exists():
        sys.exit(f'REFUSING TO RUN: no model at {d} - run build_unified_v3.py')
    q = query(Model(d), args.key)
    if args.json:
        print(json.dumps(q, indent=1, sort_keys=True, ensure_ascii=False))
        return 0 if q['found'] else 1
    return summarise(q)


if __name__ == '__main__':
    sys.exit(main())
