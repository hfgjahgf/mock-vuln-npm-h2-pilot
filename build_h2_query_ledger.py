"""Synthesise the H2 query set, deterministically, and write it down.

h2-protocol-2 said installed_version would be "deterministically synthesised from the
affected range, rule recorded in the query ledger". There was no synthesis function and
no ledger - the rule existed only as a sentence, which is the same shape as the branch
rule that was deferred and then turned out to be wrong. So it is written here.

THE RULE

  For each (entity, canonical package) pair:

    1. collect every affected range any source declares for the pair, converted to
       standard npm spelling by npm_range_h2 (which converts, and decides nothing);
    2. installed_version = the NEWEST version npm actually published on or before the
       corpus window end that is still inside one of those ranges (npm's maxSatisfying
       against the frozen registry snapshot). Newest, not the range's lower boundary: a
       query pinned to the start of a branch is the one query a wrong branch rule always
       gets right, and would leave the rule untested;
    3. no synthetic fallback. A pair with no published version inside any affected range
       is recorded as skipped rather than given an invented install;
    4. record, per source, which of ITS OWN ranges contains installed_version and what
       remediation that source STATES for that range - never the range's upper bound.

  Step 4 is per-arm on purpose. If the ledger recorded one "correct" fixed version taken
  from all sources at once, that answer would be Unified's answer, and Unified would be
  graded against itself - the tautology h2-protocol-2 was rewritten to remove. The
  ledger fixes the QUESTION; each arm answers it from its own evidence.

Every version comparison and range membership here is a lookup in
schemas/H2_RANGE_DECISIONS.json. Nothing in this file decides npm semantics.

    python build_h2_query_ledger.py            # write the ledger
    python build_h2_query_ledger.py --check    # rebuild and compare byte for byte
"""
import hashlib
import json
import sys
from pathlib import Path

import npm_range_h2 as NR

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / 'h2_query_ledger.json'
SOURCES = ('ghsa', 'nvd', 'osv')          # declared order, used to break every tie


REGISTRY = ROOT / 'schemas' / 'H2_NPM_REGISTRY_SNAPSHOT.json'
COVERAGE = ROOT / 'output' / 'h1_discovery' / 'h1_coverage_stats.json'


def snapshot_T():
    """The day this study's world was frozen, as H1 already recorded it.

    R30e-P0. Availability was being judged against each advisory's own `modified` date,
    which answers "was the fix on the registry when this source said it was the fix" -
    a question about the source's internal consistency, and much closer to H1's temporal
    fragmentation work than to H2. H2 asks something else: at the moment the snapshot
    was taken, could a CI/CD system have obtained an executable fix? That is one date
    for the whole study, and H1 froze it long ago.
    """
    return json.loads(COVERAGE.read_text(encoding='utf-8'))['snapshot_T']


def observation_times(model=NR.MODEL):
    """record_ref -> the day the source last wrote this record.

    R30d-P0. "Executable remediation" has to mean the version could actually be
    installed, and that is a question about a date: was the fix on the registry when the
    source said it was the fix? `modified` is used rather than `published` because an
    advisory that is later updated to add a fixed version is asserting that fix at the
    time of the update, not at first publication; the ledger records which field it used
    so the choice is visible rather than buried, and the `published` reading is a
    declared sensitivity arm.
    """
    out = {}
    for r in NR.rows(model / 'source_records.jsonl.gz'):
        stamp = r.get('modified') or r.get('published')
        which = 'modified' if r.get('modified') else 'published'
        if stamp:
            out[r['record_ref']] = (str(stamp)[:10], which)
    return out


def registry():
    doc = json.loads(REGISTRY.read_text(encoding='utf-8'))
    return doc['published'], doc['window_end'], doc.get('retrieved_at')


def fix_availability(package, version, observed_on, published, snapshot_day):
    """Could this declared fix have been installed at the snapshot?

    The primary reading is the whole study's snapshot date. The advisory's own
    observation date is recorded beside it so the temporal-consistency arm - "had the
    fix been published when the source named it?" - can be computed without rebuilding
    anything, but that arm answers a different question and is not the endpoint.

    Absence is reported as absence. `registry_absent_at_retrieval` says exactly what is
    known: the version was not in the registry when the snapshot was fetched. It does
    NOT say the version never existed - a package unpublished before retrieval looks
    identical from here, which the snapshot's own limitation note states. Calling it
    "not published" would claim more than the evidence carries.
    """
    day = (published.get(package) or {}).get(version)
    if day is None:
        return {'published_on': None,
                'verdict': 'registry_absent_at_retrieval',
                'installable_at_snapshot': None,
                'published_before_source_observed_it': None}
    return {
        'published_on': day,
        'verdict': ('published_by_snapshot_T' if day <= snapshot_day
                    else 'published_after_snapshot_T'),
        'installable_at_snapshot': day <= snapshot_day,
        # For the declared sensitivity arm only. Dates are day-resolution on both sides,
        # so same-day cases cannot be ordered; they are reported as `same_day`.
        'published_before_source_observed_it': (
            None if not observed_on else
            'same_day' if day == observed_on else day < observed_on),
    }


def _blank():
    return {'ranges': {}, 'fixes': {}, 'range_fix': {}, 'range_note': {},
            'evidence': {}}


def collect_pairs(model=NR.MODEL):
    """(entity, package) -> per-source ranges and fixed versions."""
    pairs = {}
    for row in NR.npm_rows(model):
        entry = pairs.setdefault((row.entity_id, row.package), _blank())
        for e in NR.affected_ranges(row):
            key = (row.source, e['range'])
            entry['ranges'].setdefault(row.source, {}).setdefault(
                e['range'], []).append(e['shape'])
            # Real provenance: the record and the pointer a reader can follow, not a
            # description of where the value came from (R30d-P1).
            entry['evidence'].setdefault(key, []).append(
                {'record_ref': e['record_ref'], 'range_pointer': e['range_pointer'],
                 'fix': e['fix'], 'fix_pointer': e['fix_pointer']})
            # The remediation the source states FOR THIS RANGE. Never the range's own
            # upper bound: that is where the source stopped saying "affected", not
            # where it says the problem was fixed.
            if e['fix']:
                entry['range_fix'].setdefault(key, set()).add(e['fix'])
            if e['note']:
                entry['range_note'].setdefault(key, set()).add(e['note'])
        fixed = NR._clean(row.payload.get('first_patched_version'))
        if fixed:
            entry['fixes'].setdefault(row.source, set()).add(fixed)
    return pairs


def choose_installed(pkg, all_ranges):
    """The newest version npm really published that is still inside an affected range.

    R30c-P1. The previous rule drew candidates from whatever strings the advisories
    mentioned - range boundaries, fixed versions, and the synthetic `0.0.0` that
    stood in for `introduced: "0"`. 329 of 3,044 queries came out at 0.0.0, a version
    npm never published, and calling that a real CI/CD query was not honest.

    Candidates are now the registry snapshot: versions published on or before the
    corpus window end, chosen by npm's own maxSatisfying. There is no synthetic
    fallback. A pair with no published version inside any affected range carries no
    query and is recorded as skipped - inventing one would undo the correction.
    """
    best = []
    for r in all_ranges:
        got = NR.max_published_satisfying(pkg, r)
        if got:
            best.append(got)
    if not best:
        return None, 'no_published_version_inside_an_affected_range'
    order = NR.sorted_versions(pkg)['ordered']
    inside = [v for v in order if v in set(best)]
    if not inside:               # ordering comes from the ledger, never from here
        raise NR.LedgerMiss(f'maxSatisfying returned {best!r} but {pkg!r} has no'
                            f' recorded order for them')
    return inside[-1], 'newest_published_version_inside_an_affected_range'


def containing(source_ranges, installed):
    """Which of this source's ranges contains the installed version."""
    return sorted(r for r in source_ranges if NR.satisfies(installed, r))


def build(model=NR.MODEL):
    pairs = collect_pairs(model)
    observed = observation_times(model)
    published, window_end, retrieved_at = registry()
    snapshot_day = snapshot_T()
    # Every cohort pair must come out the other side as a query or as a recorded skip.
    # Three pairs (markdown-it, angular, sanitize-html) are in the cohort only because
    # NVD names them through a registry URL, and that evidence never becomes an affected
    # row keyed to the canonical package - so they have no range and must say so out
    # loud. A pair that simply disappears is a denominator that quietly shrank.
    for key in NR.cohort_pairs(model):
        pairs.setdefault(key, _blank())
    queries, skipped = [], []
    for (eid, pkg) in sorted(pairs):
        entry = pairs[(eid, pkg)]
        all_ranges = sorted({r for by in entry['ranges'].values() for r in by})
        if not all_ranges:
            skipped.append({'entity_id': eid, 'package': pkg,
                            'why': 'no source declares an affected range'})
            continue
        installed, why = choose_installed(pkg, all_ranges)
        if installed is None:
            skipped.append({'entity_id': eid, 'package': pkg, 'why': why})
            continue
        per_source = {}
        for source in SOURCES:
            src_ranges = entry['ranges'].get(source) or {}
            hits = containing(src_ranges, installed)
            # What THIS source states as the remediation for the range the install
            # is inside. Recorded per source, never unioned, and never inferred from
            # the range's upper bound.
            branch_fix = sorted({f for r in hits
                                 for f in (entry['range_fix'].get((source, r)) or ())})
            notes = sorted({n for r in hits
                            for n in (entry['range_note'].get((source, r)) or ())})
            proxies = sorted({NR.structural_upper_bound(r) for r in hits} - {None})
            evidence = [e for r in hits
                        for e in (entry['evidence'].get((source, r)) or ())]
            # When did this source last write these records? Recorded for the
            # TEMPORAL-CONSISTENCY sensitivity arm only - the primary reading judges
            # availability against snapshot_T, one date for the whole study (R30e).
            days = sorted({observed[e['record_ref']][0] for e in evidence
                           if e['record_ref'] in observed})
            observed_on = days[-1] if days else None
            fields = sorted({observed[e['record_ref']][1] for e in evidence
                             if e['record_ref'] in observed})
            availability = {f: fix_availability(pkg, f, observed_on, published,
                                                snapshot_day)
                            for f in branch_fix}
            per_source[source] = {
                'declares_ranges': sorted(src_ranges),
                'ranges_containing_installed': hits,
                'branch_fix_stated_for_containing_range': branch_fix,
                'branch_fix_availability': availability,
                'source_observed_on': observed_on,
                'source_observed_field': fields,
                'structural_upper_bound_proxy': proxies,
                'notes': notes,
                'evidence': evidence,
                'declared_fixed_versions': sorted(entry['fixes'].get(source) or ()),
            }
        queries.append({
            'entity_id': eid,
            'package': pkg,
            'installed_version': installed,
            'installed_version_rule': why,
            'affected_ranges': all_ranges,
            'by_source': per_source,
        })
    doc = {
        # R30e-P2: the shape changed incompatibly twice (evidence entries, then
        # availability verdicts) while the version string stayed at /1. A version that
        # never moves cannot warn anyone that a consumer needs updating.
        'schema': 'h2-query-ledger/2',
        'note': ('One query per (entity, canonical npm package). The ledger fixes the '
                 'question; each arm answers it from its own evidence.'),
        'decisions_sha256': hashlib.sha256(NR.DECISIONS.read_bytes()).hexdigest(),
        'registry_snapshot_sha256':
            hashlib.sha256(REGISTRY.read_bytes()).hexdigest(),
        'registry_retrieved_at': retrieved_at,
        'window_end': window_end,
        'snapshot_T': snapshot_day,
        'availability_note': (
            'Primary reading: was the declared fix published by snapshot_T, the date '
            'this study froze. The advisory-relative reading is recorded per fix for '
            'the temporal-consistency sensitivity arm and is not the endpoint. '
            'registry_absent_at_retrieval states what is known - the version was not in '
            'the registry when it was fetched - and does not claim it never existed.'),
        'skipped_disposition': (
            'Excluded BEFORE the endpoint. A skipped pair carries no constructable '
            'query, so it counts as neither a success nor a failure for any arm and '
            'enters no denominator. Reported separately, never folded into a rate.'),
        'counts': {'queries': len(queries), 'skipped': len(skipped)},
        'queries': queries,
        'skipped': skipped,
    }
    return doc


def serialise(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True)
            .replace('\r\n', '\n') + '\n').encode('utf-8')


def main():
    doc = build()
    data = serialise(doc)
    if '--check' in sys.argv:
        if not LEDGER.exists():
            print('no ledger on disk to check against')
            return 1
        same = LEDGER.read_bytes() == data
        print(f"{'IDENTICAL' if same else 'DIFFERS'}: rebuilt {len(data):,} bytes "
              f"sha256 {hashlib.sha256(data).hexdigest()[:16]}...")
        return 0 if same else 1
    LEDGER.write_bytes(data)
    q = doc['queries']
    rule = {}
    for row in q:
        rule[row['installed_version_rule']] = rule.get(row['installed_version_rule'], 0) + 1
    print(f"{LEDGER.name}: queries {len(q):,} | skipped {len(doc['skipped']):,}")
    print(f"  installed_version rule: {rule}")
    print(f"  sha256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
