"""Grade every frozen query, arm by arm, into one of the seven declared outcomes.

WHAT THIS IS AND IS NOT

  It is the classifier h2-protocol-7 §4 describes: for each query in the frozen ledger
  and each of the four arms, decide what that arm returned. It produces counts and a
  per-query record, and NOTHING ELSE - no p-value, no interval, no Holm correction, no
  verdict on H2. The inference is a separate round that runs once, after this gate
  passes, using `stats_h2`.

  Every input is already frozen: the query ledger, the offline npm decision ledger, the
  registry snapshot, and the sealed model. No network, no Node.

THE THREE RULES THAT ARE EASY TO GET WRONG

  * an arm is graded on ITS OWN evidence. Unified sees all three sources; NVD-only sees
    NVD. Grading a single-source arm against the union would be grading it against
    Unified's answer, which is the tautology h2-protocol-2 was rewritten to remove;
  * a cross-source conflict fails UNIFIED ONLY. A single-source arm cannot see an
    argument between the other two, and failing it for that argument would be marking it
    down for somebody else's disagreement (§6, made unambiguous in §4 by R31);
  * a declared fix must have been installable at snapshot_T. Naming a version that was
    not on the registry that day is not an executable remediation.

    python score_h2.py            # write the scores
    python score_h2.py --check    # rebuild and compare byte for byte
"""
import hashlib
import json
import sys
from pathlib import Path

import npm_range_h2 as NR
import semver_h2 as SV

ROOT = Path(__file__).resolve().parent
MODEL = ROOT / 'output' / 'unified_model_v3'
H1 = ROOT / 'output' / 'h1_discovery'
QUERIES = ROOT / 'h2_query_ledger.json'
OUT = ROOT / 'h2_scores.json'

SOURCES = ('ghsa', 'nvd', 'osv')          # declared order, breaks every tie
ARMS = SOURCES + ('unified',)
OUTCOMES = ('success', 'package_but_no_fix', 'covered_but_no_package', 'not_covered',
            'untraceable_or_invalid', 'ambiguous_or_conflicting', 'range_disagreement')
# NOT an outcome. R33-P1: recording it as an eighth `outcome` value put it in the same
# field as the seven the protocol freezes, and every such row was also flagged
# `determinate: true` - "this arm answered N/A" and "this arm's answer is readable as
# its own" at the same time. Hospital B holds no chart under hospital A's number: that
# is not a question B can answer, so it is an ELIGIBILITY fact, kept in its own field,
# with `outcome: null`, `comparable: false`, and no place in any denominator.
NOT_COMPARABLE = 'not_comparable'


_DETERMINACY = None


def determinacy():
    """(entity, source) -> can this arm's answer be read as its own answer?

    A second implementation of the rule the provenance gate also applies, on purpose:
    the gate compares the two, and a rule with one implementation is a rule nothing can
    disagree with. Unified is the frozen model itself, so it is always determinate.
    """
    global _DETERMINACY
    if _DETERMINACY is not None:
        return _DETERMINACY
    entities = {e['entity_id']: e for e in NR.rows(MODEL / 'entities.jsonl.gz')}
    stratum = {eid: e.get('stratum') for eid, e in entities.items()}
    sampled = {}
    for r in NR.rows(MODEL / 'entity_record_links.jsonl.gz'):
        sampled.setdefault((r['entity_id'], r['source']), set()).add(r['native_id'])
    index = {s: {} for s in SOURCES}
    for s in SOURCES:
        for r in NR.rows(H1 / f'{s}_full_index.jsonl.gz'):
            eco = [str(x).lower() for x in (r.get('ecosystems') or [])]
            npm = None if 'ecosystems' not in r else any(
                x == 'npm' or x.startswith('npm:') for x in eco)
            for ident in [r.get('id')] + list(r.get('aliases') or []):
                if isinstance(ident, str) and ident.upper().startswith('CVE-'):
                    index[s].setdefault(ident.upper(), []).append((r['id'], npm))

    out = {}
    for eid, entity in entities.items():
        cve = (entity.get('preferred_identifier') or '').upper()
        for s in SOURCES:
            relevant = [rid for rid, npm in index[s].get(cve, []) if npm is not False]
            out[(eid, s)] = (True if not relevant else
                             all(r in sampled.get((eid, s), set()) for r in relevant))
    _DETERMINACY = (out, sampled, stratum)
    return _DETERMINACY


def arm_view(query, arm):
    """What this arm - and only this arm - has to say about this query."""
    if arm != 'unified':
        b = query['by_source'][arm]
        return {'ranges': list(b['declares_ranges']),
                'containing': list(b['ranges_containing_installed']),
                'fixes': list(b['branch_fix_stated_for_containing_range']),
                'availability': dict(b.get('branch_fix_availability') or {}),
                'evidence': list(b.get('evidence') or []),
                'by_source_fixes': {}}
    ranges, containing, fixes, availability, evidence = [], [], [], {}, []
    by_source_fixes = {}
    for s in SOURCES:
        b = query['by_source'][s]
        ranges += b['declares_ranges']
        containing += b['ranges_containing_installed']
        fixes += b['branch_fix_stated_for_containing_range']
        availability.update(b.get('branch_fix_availability') or {})
        evidence += b.get('evidence') or []
        if b['branch_fix_stated_for_containing_range']:
            by_source_fixes[s] = list(b['branch_fix_stated_for_containing_range'])
    return {'ranges': ranges, 'containing': containing, 'fixes': fixes,
            'availability': availability, 'evidence': evidence,
            'by_source_fixes': by_source_fixes}


def grade(query, arm, covers_entity, native_owner=None):
    """One of the seven outcomes, in the order h2-protocol-7 §4 sets out.

    `native_owner` is set for the no-CVE stratum, whose entities are keyed
    `native:<source>:<id>`. Any other single-source arm cannot be paired there at all
    (§3.1), and this decision belongs HERE rather than in the caller: a classifier that
    does not make all of its own decisions cannot be re-run to check the output, which
    is how a misclassification survived the first version of the gate.
    """
    if native_owner and arm != 'unified' and arm != native_owner:
        # None, not an outcome: there is no question here to answer well or badly.
        return None, (f'no-CVE stratum: the entity is keyed to {native_owner}, so '
                      f'{arm} cannot be paired on it')
    v = arm_view(query, arm)

    if not v['ranges']:
        # Nothing about this package from this arm. Whether it knows the vulnerability
        # at all is what separates the two "no answer" classes.
        return ('covered_but_no_package' if covers_entity else 'not_covered'), None

    if not v['containing']:
        # The arm has ranges for this package and places the install outside all of
        # them: it says this version is not affected. That is a disagreement about the
        # range, not an absence of data.
        return 'range_disagreement', 'installed version is outside every declared range'

    if not v['fixes']:
        return 'package_but_no_fix', None

    # Traceability: something has to point back at a record and a location in it.
    if not any(e.get('record_ref') and e.get('range_pointer') for e in v['evidence']):
        return 'untraceable_or_invalid', 'no record_ref and pointer behind the advice'

    # Parseability, decided by the frozen npm ledger and never here.
    unparseable = [f for f in v['fixes'] if not NR.parsed(f).get('valid')]
    if unparseable:
        return 'untraceable_or_invalid', f'unparseable fixed version {unparseable[0]}'

    # Installable at the snapshot. A version that was not on the registry that day is
    # not an executable remediation.
    not_installable = [f for f in v['fixes']
                       if v['availability'].get(f, {}).get('installable_at_snapshot')
                       is not True]
    if not_installable:
        verdict = v['availability'].get(not_installable[0], {}).get('verdict')
        return 'untraceable_or_invalid', f'declared fix {not_installable[0]}: {verdict}'

    # Ambiguity. Unified answers for everyone, so a disagreement between sources is its
    # problem; a single-source arm is only asked whether ITS OWN advice is unique.
    if arm == 'unified':
        if len(v['by_source_fixes']) > 1 and SV.conflicting_candidate_sets(
                v['by_source_fixes']):
            return 'ambiguous_or_conflicting', 'sources disagree about the fixed version'
    if len({SV.render(SV.parse(f)) for f in v['fixes'] if SV.parse(f)}) > 1:
        return 'ambiguous_or_conflicting', 'more than one fix for the applicable branch'

    return 'success', None


def build():
    ledger = json.loads(QUERIES.read_text(encoding='utf-8'))
    det, sampled, stratum = determinacy()
    # Which source owns each no-CVE entity, from its own preferred identifier.
    ledger_native_source = {}
    for e in NR.rows(MODEL / 'entities.jsonl.gz'):
        ident = e.get('preferred_identifier') or ''
        if ident.startswith('native:'):
            ledger_native_source[e['entity_id']] = ident.split(':')[1]

    rows, counts, determinate_counts = [], {}, {}
    not_comparable = {arm: 0 for arm in ARMS}
    for arm in ARMS:
        counts[arm] = {o: 0 for o in OUTCOMES}
        # Per stratum, because §3.1 forbids folding the no-CVE layer into the paired
        # comparisons: it is single-source by construction and cannot be paired.
        determinate_counts[arm] = {'cve_keyed': 0, 'no_direct_cve_identity': 0}
    for q in ledger['queries']:
        eid = q['entity_id']
        layer = stratum.get(eid) or 'unknown'
        native_source = (ledger_native_source.get(eid)
                         if layer != 'cve_keyed' else None)
        row = {'entity_id': eid, 'package': q['package'], 'stratum': layer,
               'installed_version': q['installed_version'], 'by_arm': {}}
        for arm in ARMS:
            covers = arm != 'unified' and bool(sampled.get((eid, arm)))
            if arm == 'unified':
                covers = any(sampled.get((eid, s)) for s in SOURCES)
            outcome, why = grade(q, arm, covers, native_source)
            comparable = outcome is not None
            # An arm that cannot be asked is not determinate either - determinacy
            # says whether ITS answer reads as its own, and there is no answer.
            # Counting these as determinate inflated every no-CVE denominator.
            determinate = (comparable
                           and (True if arm == 'unified'
                                else det.get((eid, arm), False)))
            row['by_arm'][arm] = {'outcome': outcome, 'why': why,
                                  'comparable': comparable,
                                  'disposition': None if comparable
                                                 else NOT_COMPARABLE,
                                  'determinate': determinate}
            if comparable:
                counts[arm][outcome] += 1
            else:
                not_comparable[arm] += 1
            if determinate and layer in determinate_counts[arm]:
                determinate_counts[arm][layer] += 1
        rows.append(row)

    return {
        'schema': 'h2-scores/2',
        'note': ('Outcome classification only. No p-value, no interval, no correction, '
                 'no verdict on H2 - the inference is a separate run.'),
        'query_ledger_sha256': hashlib.sha256(QUERIES.read_bytes()).hexdigest(),
        'protocol_version': 'h2-protocol-8',
        'counts': counts,
        # Kept out of `counts` on purpose: an eligibility fact is not an outcome.
        'not_comparable': not_comparable,
        'determinate_queries': determinate_counts,
        'scored_queries': len(rows),
        'excluded_before_endpoint': len(ledger.get('skipped', [])),
        'scores': rows,
    }


def serialise(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True)
            .replace('\r\n', '\n') + '\n').encode('utf-8')


def main():
    doc = build()
    data = serialise(doc)
    if '--check' in sys.argv:
        if not OUT.exists():
            print('no scores on disk to check against')
            return 1
        same = OUT.read_bytes() == data
        print(f"{'IDENTICAL' if same else 'DIFFERS'}: rebuilt {len(data):,} bytes "
              f"sha256 {hashlib.sha256(data).hexdigest()[:16]}...")
        return 0 if same else 1
    OUT.write_bytes(data)
    print(f"scored {doc['scored_queries']:,} queries | excluded before the endpoint "
          f"{doc['excluded_before_endpoint']}")
    for arm in ARMS:
        line = ' '.join(f'{o}={doc["counts"][arm][o]}' for o in OUTCOMES
                        if doc['counts'][arm].get(o))
        line += f' | not_comparable={doc["not_comparable"][arm]}'
        d = doc['determinate_queries'][arm]
        print(f"  {arm:8} determinate cve-keyed {d['cve_keyed']:>5,} + no-CVE "
              f"{d['no_direct_cve_identity']:>4,} | {line}")
    print(f'{OUT.name}: sha256 {hashlib.sha256(data).hexdigest()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
