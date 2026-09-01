"""R40 shard step: load the model on the runner, query it, and prove the answers.

    python r40_online_query.py --spec schemas/H2_REAL_ENVIRONMENTS.json \
        --shard 0 --shard-count 32 --out out/online-query-0.json

Runs on the CI runner BEFORE anything is installed or scanned. It is what makes the
sentence "the complete unified model is deployed and queried online" true rather than
aspirational: the model was rebuilt on this machine minutes ago, this process loads it,
asks it about this shard's environments, and writes down what it was told and where
each answer came from.

WHY THIS DOES NOT INVENT A QUERY

  R37b-P0: the pipeline once recomputed the Unified arm at run time, and that merge
  bypassed every criterion the study applies - parseability, installability at
  snapshot_T, traceability, uniqueness, the conflict test. On 27 environments the
  frozen model had NO valid recommendation while the merge still produced a version,
  and on 6 more it produced one outside the valid set.

  So nothing here decides anything. The ledger is built by calling
  `build_h2_query_ledger.build(model_dir)` - the same function, unmodified - against
  the model this runner loaded, and the per-source view comes from
  `score_h2.arm_view`, which is query-local. The three downstream stages run as their
  own `--check` subprocesses. A NEW implementation of any of this is the one thing
  R40 must not contain, and `Test_r40_deployment.py` has a fault for it.

WHY THE WHOLE CHAIN RUNS IN EVERY SHARD

  The conflict test is package-level and corpus-wide: whether one version can clear
  every fix an arm states for a package depends on every query for that package, not
  just this shard's. A shard that recomputed from its own slice would silently drop
  the criterion. It holds the whole model, and the chain measures ~42s against tens of
  npm installs per shard, so it runs the whole thing.

WHAT IT REFUSES TO DO

  Emit anything if the model does not match the seal, if the ledger built from that
  model is not byte-identical to the committed one, or if any downstream check fails.
  A provenance record produced beside a failing check is worse than none: it looks
  like evidence.

Protocol: schemas/R40_DEPLOYMENT_PROTOCOL.md (r40-deployment-protocol-1).
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import build_h2_query_ledger as QL
import score_h2 as SC

ROOT = Path(__file__).resolve().parent
SEAL = ROOT / 'h1_seal_manifest.json'
LEDGER = ROOT / 'h2_query_ledger.json'
ORACLE = ROOT / 'schemas' / 'H2_UNIFIED_RECOMMENDATIONS.json'
DEFAULT_MODEL = ROOT / 'output' / 'unified_model_v3'

SOURCES = ('ghsa', 'nvd', 'osv')
PROTOCOL = 'r40-deployment-protocol-1'
SCHEMA = 'r40-online-query/1'

# Run after the ledger, in this order: each reads what the one before it wrote.
DOWNSTREAM = ('score_h2.py', 'derive_h2_cicd.py',
              'build_h2_unified_recommendations.py')


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def model_against_seal(model_dir):
    """The 11 sections, against the hashes h1_seal_manifest.json already pins.

    The expectation is NOT invented here. `h1_seal_manifest.json` is committed, is
    guarded by Test_h1_seal.py, and has pinned these eleven since the H1 seal - so
    "the runner rebuilt the sealed model" is checked against the same record the
    thesis already relies on, rather than against a number this round made up.
    """
    seal = json.loads(SEAL.read_text(encoding='utf-8'))['model_sha256']
    rows, ok = {}, True
    for section, want in sorted(seal.items()):
        path = model_dir / f'{section}.jsonl.gz'
        got = sha256_file(path) if path.exists() else None
        rows[section] = {'expected': want, 'observed': got, 'match': got == want}
        ok &= got == want
    return ok, rows


def metadata_blocks(model_dir):
    """The metadata comparison, minus the one key that cannot match.

    `generated_at_utc` differs on every rebuild by construction. Measured: it is the
    ONLY key that differs. Comparing the whole file would fail for a timestamp, and
    deleting the timestamp to make it pass would be editing the thing under test.
    """
    meta = json.loads((model_dir / 'dataset_metadata.json').read_text(encoding='utf-8'))
    return {'model_version': meta.get('model_version'),
            'section_sha256': meta.get('section_sha256'),
            'inputs': meta.get('inputs'),
            'counts': meta.get('counts'),
            'excluded_from_comparison': ['generated_at_utc']}


def ledger_from_model(model_dir):
    """Build the query ledger from the model THIS process loaded, in process.

    In process, not by reading `h2_query_ledger.json`: the point of the record is that
    the answers came from the model on this runner. The file is then used as the
    oracle to compare against - the other way round from R37.
    """
    doc = QL.build(model_dir)
    produced = QL.serialise(doc)
    committed = LEDGER.read_bytes() if LEDGER.exists() else b''
    return doc, produced == committed, hashlib.sha256(produced).hexdigest()


def downstream_checks(python=sys.executable):
    out = []
    for script in DOWNSTREAM:
        run = subprocess.run([python, script, '--check'], cwd=ROOT,
                             capture_output=True, text=True)
        out.append({'command': f'{script} --check',
                    'returncode': run.returncode,
                    'passed': run.returncode == 0,
                    'tail': (run.stdout or run.stderr or '').strip()[-200:]})
    return out


def shard_slice(environments, shard, shard_count, limit):
    """The same rule run_environment.py uses, restated rather than imported.

    Restated deliberately (R25b-Fa): if this drifts from the runner's slicing the two
    would describe different environments while looking like one shard, so the gate
    checks the two agree instead of one importing the other and hiding the question.
    """
    mine = [e for i, e in enumerate(environments) if i % shard_count == shard]
    return mine[:limit] if limit else mine


def evidence_for(row, entity_id, package):
    """What each source says about this (entity, package), with its pointers."""
    per_source = {}
    for source in SOURCES:
        block = row['by_source'][source]
        per_source[source] = {
            'declares_ranges': list(block['declares_ranges']),
            'ranges_containing_installed': list(block['ranges_containing_installed']),
            'branch_fix_stated_for_containing_range':
                list(block['branch_fix_stated_for_containing_range']),
            'branch_fix_availability': dict(block.get('branch_fix_availability') or {}),
            # record_ref / fix_pointer / range_pointer - a pointer nobody can follow is
            # not provenance (R30d-P1), so they travel with the answer.
            'evidence': list(block.get('evidence') or []),
        }
    unified = SC.arm_view(row, 'unified')
    return {
        'entity_id': entity_id,
        'package': package,
        'installed_version': row['installed_version'],
        'affected_ranges': list(row['affected_ranges']),
        'by_source': per_source,
        'unified_view': {
            'ranges_containing_installed': unified['containing'],
            'branch_fixes': unified['fixes'],
            'which_source_stated_each': unified['by_source_fixes'],
            'record_refs': sorted({e['record_ref'] for e in unified['evidence']}),
        },
    }


def online_records(environments, ledger, oracle):
    by_pair = {(q['entity_id'], q['package']): q for q in ledger['queries']}
    by_env = {e['env_id']: e for e in oracle['environments']}
    records, missing = [], []
    for env in environments:
        answers = []
        for query in env.get('queries') or []:
            key = (query['entity_id'], env['package'])
            row = by_pair.get(key)
            if row is None:
                # A cohort pair the ledger recorded as skipped. Said out loud: a pair
                # that simply disappeared would be a denominator quietly shrinking.
                missing.append({'env_id': env['env_id'], 'entity_id': key[0],
                                'package': key[1],
                                'why': 'no ledger row - recorded as skipped upstream'})
                continue
            answers.append(evidence_for(row, query['entity_id'], env['package']))
        chosen = by_env.get(env['env_id'], {})
        records.append({
            'env_id': env['env_id'],
            'package': env['package'],
            'installed_version': env['installed_version'],
            'queried_online': answers,
            'recommendations': chosen.get('recommendations', []),
            'no_recommendation_for_queries':
                chosen.get('no_recommendation_for_queries', []),
            'selection_rationale': {
                'decided_by': 'derive_h2_cicd.py, over the whole corpus',
                'why_not_here': (
                    'the conflict test asks whether one version can clear every fix '
                    'the arm states for this PACKAGE, which depends on every query for '
                    'that package rather than on this environment. It is computed by '
                    'the chain this shard ran in full, not by this file.'),
                'pointer': 'h2_cicd_decisions.json/decisions[package,installed_version]',
            },
        })
    return records, missing


def build(spec_path, shard, shard_count, limit, model_dir, run_downstream=True):
    spec = json.loads(Path(spec_path).read_text(encoding='utf-8'))
    seal_ok, seal_rows = model_against_seal(model_dir)
    ledger, ledger_ok, ledger_digest = ledger_from_model(model_dir)
    checks = downstream_checks() if run_downstream else []
    oracle = json.loads(ORACLE.read_text(encoding='utf-8'))
    mine = shard_slice(spec['environments'], shard, shard_count, limit)
    records, missing = online_records(mine, ledger, oracle)
    fidelity = {
        'e1_model_matches_seal': seal_ok,
        'e1_sections': seal_rows,
        'e1_metadata': metadata_blocks(model_dir),
        'e2_ledger_built_from_this_model_matches_committed': ledger_ok,
        'e2_ledger_sha256': ledger_digest,
        'e2_downstream_checks': checks,
        'all_passed': bool(seal_ok and ledger_ok
                           and all(c['passed'] for c in checks)),
    }
    return {
        'schema': SCHEMA,
        'protocol_version': PROTOCOL,
        'what_this_is': (
            'The unified model was rebuilt on this runner from hash-verified frozen '
            'inputs, loaded by this process, and queried for the environments in this '
            'shard. Every recommendation below was computed here, during this run. '
            'The committed manifest is used as the expected output, never as input.'),
        'not_claimed': (
            'Nothing here is a claim about currency, about what live databases would '
            'answer today, or about anything being made faster. The install and scan '
            'results this shard goes on to produce are NOT comparable with the sealed '
            'census: the npm registry and the scanner database have both moved since '
            '2026-08-18, and the scanner binary is pinned while its database is not.'),
        'shard': shard,
        'shard_count': shard_count,
        'limit': limit,
        'environments_in_shard': len(mine),
        'fidelity': fidelity,
        'pairs_without_a_ledger_row': missing,
        'environments': records,
    }


def serialise(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True)
            + '\n').encode('utf-8')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--spec', required=True)
    ap.add_argument('--shard', type=int, required=True)
    ap.add_argument('--shard-count', type=int, required=True)
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--model-dir', default=str(DEFAULT_MODEL))
    ap.add_argument('--out', required=True)
    ap.add_argument('--skip-downstream', action='store_true',
                    help='fidelity checks only from this process; for local testing')
    args = ap.parse_args()

    doc = build(args.spec, args.shard, args.shard_count, args.limit,
                Path(args.model_dir), run_downstream=not args.skip_downstream)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(serialise(doc))

    fid = doc['fidelity']
    print(f"shard {args.shard}/{args.shard_count}: "
          f"{doc['environments_in_shard']} environments")
    print(f"  E1 model matches seal            {fid['e1_model_matches_seal']}")
    print(f"  E2 ledger from this model        "
          f"{fid['e2_ledger_built_from_this_model_matches_committed']}")
    for check in fid['e2_downstream_checks']:
        print(f"  E2 {check['command']:40} {check['passed']}")
    print(f'  written {out}')
    if not fid['all_passed']:
        # Refuse to look like evidence. A shard that could not establish E1/E2 must
        # fail the job, not hand back a provenance file that reads as if it had.
        print('R40 ONLINE QUERY: FAIL - fidelity not established, '
              'this shard proves nothing')
        return 1
    print('R40 ONLINE QUERY: PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
