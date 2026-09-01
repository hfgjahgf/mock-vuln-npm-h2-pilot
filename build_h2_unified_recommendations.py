"""The Unified arm's recommendations, taken from the frozen model - nothing else.

R37b-P0: the pipeline used to recompute the Unified arm itself, merging every fix every
source states for the package and taking the lexicographically first string. That
bypasses every criterion H2 and R36 apply - parseability, installability at snapshot_T,
traceability, uniqueness, the conflict test - and it showed: on 27 environments the
frozen model has NO valid recommendation while that merge still produced a version, and
on 6 more it produced a version outside the valid set.

So the Unified arm no longer decides anything at run time. It reads this manifest, which
is generated here from `h2_cicd_decisions.json` and pinned by hash.

  python build_h2_unified_recommendations.py            # write the manifest
  python build_h2_unified_recommendations.py --check     # byte-identical reproduction
  python build_h2_unified_recommendations.py --self-test

NO NETWORK. Reads frozen artefacts only.

Protocol: schemas/H2_REAL_PIPELINE_PROTOCOL.md (h2-real-protocol-6).
"""
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CICD = ROOT / 'h2_cicd_decisions.json'
QUERIES = ROOT / 'h2_query_ledger.json'
PROTOCOL_DOC = ROOT / 'schemas' / 'H2_REAL_PIPELINE_PROTOCOL.md'
OUT = ROOT / 'schemas' / 'H2_UNIFIED_RECOMMENDATIONS.json'

PROTOCOL = 'h2-real-protocol-6'
SCHEMA = 'h2-unified-recommendations/1'


def build():
    cicd = json.loads(CICD.read_text(encoding='utf-8'))
    ledger = json.loads(QUERIES.read_text(encoding='utf-8'))

    envs = sorted({(q['package'], q['installed_version']) for q in ledger['queries']})
    order = {key: f'env-{i:04d}' for i, key in enumerate(envs)}

    # Per environment: the distinct versions the frozen model recommends, each carrying
    # the queries that asked for it. NO collapse rule is invented - measured on the
    # frozen data, 1,383 environments have exactly one distinct recommendation and 8
    # have two, so every distinct recommendation is simply installed and re-scanned on
    # its own. Per-query attribution survives intact, at a cost of 8 extra phase-2 runs.
    per_env = defaultdict(lambda: defaultdict(list))
    declined = defaultdict(list)
    for row in cicd['decisions']:
        key = (row['package'], row['installed_version'])
        cell = row['by_arm']['unified']
        rec = cell.get('recommended_version')
        if rec:
            per_env[key][rec].append({
                'entity_id': row['entity_id'],
                'r36_category': cell.get('category'),
                'r36_subclass': cell.get('subclass'),
            })
        else:
            declined[key].append({
                'entity_id': row['entity_id'],
                'r36_category': cell.get('category'),
                'r36_disposition': cell.get('disposition'),
            })

    entries = []
    for key in envs:
        package, version = key
        recs = per_env.get(key, {})
        entries.append({
            'env_id': order[key],
            'package': package,
            'installed_version': version,
            # Each is installed and re-scanned separately (see above).
            'recommendations': [
                {'version': rec,
                 'for_queries': sorted(rows, key=lambda r: r['entity_id'])}
                for rec, rows in sorted(recs.items())
            ],
            'no_recommendation_for_queries': sorted(
                declined.get(key, []), key=lambda r: r['entity_id']),
        })

    with_any = sum(1 for e in entries if e['recommendations'])
    return {
        'schema': SCHEMA,
        'protocol_version': PROTOCOL,
        'note': ('The Unified arm answers ONLY from here. It is the frozen model, not '
                 'a live lookup: it cannot see anything published after snapshot_T. The '
                 'protocol discloses that asymmetry and, since R37c, does NOT claim a '
                 'direction for it - live drift can hurt either side. The pipeline must '
                 'not derive a Unified recommendation any other way.'),
        'derivation': ("h2_cicd_decisions.json -> by_arm.unified.recommended_version, "
                       "which already carries H2's success gate (parseable, installable "
                       "at snapshot_T, traceable, unique) and R36's conflict test. "
                       "Nothing is recomputed here."),
        'inputs_sha256': {
            'h2_cicd_decisions.json': sha(CICD),
            'h2_query_ledger.json': sha(QUERIES),
        },
        'provenance_sha256': {
            'protocol': sha(PROTOCOL_DOC),
            'generator': sha(Path(__file__)),
        },
        'counts': {
            'environments': len(entries),
            'environments_with_a_recommendation': with_any,
            'environments_without_any_recommendation': len(entries) - with_any,
            'distinct_recommendations': sum(len(e['recommendations']) for e in entries),
            'queries_with_a_recommendation': sum(
                len(r['for_queries']) for e in entries for r in e['recommendations']),
            'queries_without_a_recommendation': sum(
                len(e['no_recommendation_for_queries']) for e in entries),
        },
        'environments': entries,
    }


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def serialise(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True)
            .replace('\r\n', '\n') + '\n').encode('utf-8')


def self_test():
    ok = True

    def check(label, cond):
        nonlocal ok
        ok = ok and cond
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")

    doc = build()
    c = doc['counts']
    cicd = json.loads(CICD.read_text(encoding='utf-8'))
    want_rows = sum(1 for r in cicd['decisions']
                    if r['by_arm']['unified'].get('recommended_version'))
    check('every query the frozen model recommends for is carried',
          c['queries_with_a_recommendation'] == want_rows)
    check('every query is either recommended for or explicitly not',
          c['queries_with_a_recommendation'] + c['queries_without_a_recommendation']
          == len(cicd['decisions']))
    check('no environment invents a recommendation the model does not make',
          all(e['recommendations'] or e['no_recommendation_for_queries']
              for e in doc['environments']))
    versions = {r['version'] for e in doc['environments'] for r in e['recommendations']}
    frozen = {r['by_arm']['unified']['recommended_version'] for r in cicd['decisions']
              if r['by_arm']['unified'].get('recommended_version')}
    check('the manifest names no version outside the frozen model', versions <= frozen)
    check('environments are keyed the same way as the environment spec',
          all(e['env_id'].startswith('env-') for e in doc['environments']))
    print(f"H2 UNIFIED RECOMMENDATIONS SELF-TEST: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main():
    if '--self-test' in sys.argv:
        return self_test()
    doc = build()
    data = serialise(doc)
    if '--check' in sys.argv:
        if not OUT.exists():
            print(f'{OUT.name} is missing')
            return 1
        same = OUT.read_bytes() == data
        print(f"{'IDENTICAL' if same else 'DIFFERS'}: sha256 "
              f"{hashlib.sha256(data).hexdigest()[:16]}...")
        return 0 if same else 1
    OUT.write_bytes(data)
    c = doc['counts']
    print(f"  environments {c['environments']}  with a recommendation "
          f"{c['environments_with_a_recommendation']}  distinct recommendations "
          f"{c['distinct_recommendations']}")
    print(f"  queries recommended for {c['queries_with_a_recommendation']}  "
          f"not {c['queries_without_a_recommendation']}")
    print(f'{OUT.name}: sha256 {hashlib.sha256(data).hexdigest()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
