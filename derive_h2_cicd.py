"""R36 - offline semver counterfactual replay: modelled post-remediation exposure.

H2 asked which arm can RETRIEVE an executable fix. It never asked the next question:
if the installed version were swapped for the one that arm names, which advisory ranges
in the frozen corpus would STILL contain it? This answers that, on exactly the same
frozen queries, with the same denominator, and it changes nothing about H2.

NOTHING IS INSTALLED HERE AND NO SCANNER IS RUN. Every "re-scan" in this module is a
membership test against the frozen npm semver ledger - a counterfactual on paper. The
live GitHub Actions validation, where packages really are installed and real scanners
really do run, is a separate round (R37) with its own protocol. R36b renamed this
throughout after the wording had drifted into claiming an installation.

  python derive_h2_cicd.py            # build and write h2_cicd_decisions.json
  python derive_h2_cicd.py --check    # byte-identical reproduction
  python derive_h2_cicd.py --self-test

Protocol: schemas/H2_CICD_PROTOCOL.md (h2-cicd-protocol-2). Gate: Test_h2_cicd.py.
"""
import hashlib
import json
import pathlib
import random
import sys
from collections import defaultdict
from pathlib import Path

import npm_range_h2 as NR
import score_h2 as SC

ROOT = Path(__file__).resolve().parent
QUERIES = ROOT / 'h2_query_ledger.json'
SCORES = ROOT / 'h2_scores.json'
RESULTS = ROOT / 'h2_results.json'
DECISIONS = ROOT / 'schemas' / 'H2_RANGE_DECISIONS.json'
OUT = ROOT / 'h2_cicd_decisions.json'

SOURCES = ('ghsa', 'nvd', 'osv')
ARMS = SOURCES + ('unified',)
PROTOCOL = 'h2-cicd-protocol-2'
SCHEMA = 'h2-cicd-decisions/2'
PROTOCOL_DOC = ROOT / 'schemas' / 'H2_CICD_PROTOCOL.md'
GATE = ROOT / 'Test_h2_cicd.py'

# H2 outcome -> the R36 category it lands in. Restated from h2-protocol-8 §4 rather
# than derived, so that a change on either side has to be made deliberately on both.
UNDECIDABLE_FROM = {
    'not_covered': 'not_covered',
    'covered_but_no_package': 'covered_but_no_package',
    'package_but_no_fix': 'package_but_no_fix',
    'untraceable_or_invalid': 'untraceable_or_invalid',
}
# "I think you are fine" is a decision that was MADE, not an absence of one, and the
# protocol says it is reported apart and folded into no rate. R36a: it used to sit
# inside `undecidable`, which is exactly the folding the protocol forbids. It is now a
# disposition of its own, alongside `not_comparable`, so the four categories never
# absorb it.
DECLINES_ACTION_FROM = 'range_disagreement'
CATEGORIES = ('decided', 'undecidable', 'conflict', 'post_remediation_exposure')
EXPOSURE_SUBCLASSES = ('target_advisory_persists', 'cross_advisory_residual_exposure')

BOOTSTRAP_DRAWS = 2000
BOOTSTRAP_SEED = 20260817


# --------------------------------------------------------------------------- data

def arm_ranges_by_package(ledger):
    """Every range each arm itself declares for each package, across the whole ledger.

    This is the re-scan baseline of §3: an arm is judged against what IT said, never
    against advisories it never had.
    """
    known = {a: defaultdict(set) for a in ARMS}
    for q in ledger['queries']:
        for arm in ARMS:
            known[arm][q['package']].update(SC.arm_view(q, arm)['ranges'])
    return known


def range_provenance(ledger):
    """(arm, package, range) -> the entities declaring it and the records behind them.

    A record pointer is attached only where the ledger pins it unambiguously: when the
    arm cites exactly one range for that query. Elsewhere the entity is named and the
    pointer list is left empty - the ledger records evidence per fix, not per range, and
    inventing a mapping would be provenance we do not actually have.
    """
    ents = defaultdict(set)
    refs = defaultdict(set)
    for q in ledger['queries']:
        for arm in ARMS:
            v = SC.arm_view(q, arm)
            declared = set(v['ranges'])
            for r in declared:
                ents[(arm, q['package'], r)].add(q['entity_id'])
            if len(declared) != 1:
                continue
            only = next(iter(declared))
            for e in v['evidence']:
                if e.get('record_ref') and e.get('range_pointer'):
                    refs[(arm, q['package'], only)].add(
                        (e['record_ref'], e['range_pointer']))
    return ents, refs


def residual(fix, ranges, entity_ranges, satisfies=None):
    """Which of `ranges` still contain `fix`. Raises LedgerMiss rather than guessing.

    A lookup the offline oracle never decided is a hard failure. Reading it as "not in
    range" would silently inflate `decided`, and an empty result is the shape that
    looks healthiest when nothing was actually checked (R30c).

    Returns `(ranges_still_hit, whether_any_is_this_query)`. The provenance behind each
    range lives once in a top-level index rather than on every row: the same ranges recur
    across all 745 queries of the largest package, and repeating them wrote an 86 MB file
    that no repository can hold. **Nothing is truncated** - the index is complete.

    `satisfies` exists so the self-test can drive synthetic ranges; every real call
    leaves it None and goes to the frozen npm ledger.
    """
    satisfies = satisfies or NR.satisfies
    hit = [r for r in sorted(ranges)
           if satisfies(fix, r)]              # LedgerMiss propagates on purpose
    return hit, any(r in entity_ranges for r in hit)


def residual_index(ents, refs):
    """(arm, package, range) -> who declares it and which records say so. Complete."""
    index = {}
    for (arm, package, rng), owners in ents.items():
        entry = {'declared_by_entities': sorted(owners)}
        records = sorted(refs.get((arm, package, rng), ()))
        if records:
            entry['records'] = [{'record_ref': ref, 'json_pointer': ptr}
                                for ref, ptr in records]
        index[f'{arm}|{package}|{rng}'] = entry
    return index


# --------------------------------------------------------------------------- build

def build():
    ledger = json.loads(QUERIES.read_text(encoding='utf-8'))
    scores = json.loads(SCORES.read_text(encoding='utf-8'))
    results = json.loads(RESULTS.read_text(encoding='utf-8'))

    known = arm_ranges_by_package(ledger)
    ents, refs = range_provenance(ledger)
    # §3 secondary reading: the same re-scan against every range the corpus knows for
    # that package, not just the arm's own. R36a - the protocol promised this and the
    # artefact carried only a sentence saying it existed.
    union_known = defaultdict(set)
    for q in ledger['queries']:
        union_known[q['package']].update(q['affected_ranges'])

    # Every fix each arm states for each package - the candidate set a pipeline could
    # choose from when it has to pin one version - and the ranges those fixes answer.
    stated = {a: defaultdict(set) for a in ARMS}
    answered = {a: defaultdict(set) for a in ARMS}
    for q in ledger['queries']:
        for arm in ARMS:
            v = SC.arm_view(q, arm)
            stated[arm][q['package']].update(v['fixes'])
            if v['fixes']:
                answered[arm][q['package']].update(v['containing'])

    # Which of those candidates clears the whole package, per arm. Computed once.
    # Protocol §4.2: a conflict is the arm's STATED FIXES failing to be satisfiable by
    # one version - so the test runs against the ranges those fixes answer, not against
    # every range the arm declares. An advisory with no fix at all is not contradicting
    # advice; it is absent advice, and it belongs in residual exposure.
    #
    # A candidate also has to be a version npm would accept: an unparseable string
    # satisfies NO range, so without that test it looks like the one version that clears
    # everything - `2026.03.28` (leading zero) was being offered as the remedy for a
    # package whose ranges include `>=0.0.0`, which nothing can escape. Same shape as
    # R30c: the thing with nothing to test against looks healthiest.
    satisfiable = {}
    for arm in ARMS:
        for package, fixes in stated[arm].items():
            satisfiable[(arm, package)] = [
                f for f in sorted(fixes)
                if NR.parsed(f).get('valid')
                and not residual(f, answered[arm][package], set())[0]]

    by_key = {(r['entity_id'], r['package']): r for r in scores['scores']}
    rows = []
    counts = {a: {c: 0 for c in CATEGORIES} for a in ARMS}
    subs = {a: defaultdict(int) for a in ARMS}
    not_comparable = {a: 0 for a in ARMS}
    declines = {a: 0 for a in ARMS}
    union_counts = {a: {c: 0 for c in CATEGORIES} for a in ARMS}
    union_subs = {a: defaultdict(int) for a in ARMS}

    for q in ledger['queries']:
        key = (q['entity_id'], q['package'])
        scored = by_key[key]
        row = {'entity_id': q['entity_id'], 'package': q['package'],
               'installed_version': q['installed_version'], 'by_arm': {}}
        for arm in ARMS:
            cell = scored['by_arm'][arm]
            if not cell.get('comparable'):
                row['by_arm'][arm] = {'category': None,
                                      'disposition': 'not_comparable',
                                      'why': cell.get('why')}
                not_comparable[arm] += 1
                continue

            outcome = cell['outcome']
            if outcome == DECLINES_ACTION_FROM:
                row['by_arm'][arm] = {'category': None,
                                      'disposition': 'declines_action',
                                      'h2_outcome': outcome,
                                      'why': ('the arm places the installed version '
                                              'outside every range it declares, so it '
                                              'decides no action is needed')}
                declines[arm] += 1
                continue
            if outcome in UNDECIDABLE_FROM:
                entry = {'category': 'undecidable',
                         'subclass': UNDECIDABLE_FROM[outcome],
                         'h2_outcome': outcome, 'recommended_version': None}
                union_counts[arm]['undecidable'] += 1
                union_subs[arm][UNDECIDABLE_FROM[outcome]] += 1
            elif outcome == 'ambiguous_or_conflicting':
                entry = {'category': 'conflict', 'subclass': 'within_query',
                         'h2_outcome': outcome, 'recommended_version': None}
                union_counts[arm]['conflict'] += 1
                union_subs[arm]['within_query'] += 1
            elif outcome == 'success':
                view = SC.arm_view(q, arm)
                entity_ranges = set(view['ranges'])
                package = q['package']
                recommended = sorted(set(view['fixes']))[0]
                left, hits_target = residual(recommended, known[arm][package],
                                             entity_ranges)
                base = {'h2_outcome': outcome, 'recommended_version': recommended,
                        'residual_ranges': left,
                        'residual_range_count': len(left),
                        'residual_includes_this_query': hits_target}
                # The secondary reading, recorded per row so the two are never mixed.
                u_left, u_hits = residual(recommended, union_known[package],
                                          entity_ranges)
                if not satisfiable[(arm, package)]:
                    u_cat, u_sub = 'conflict', 'package_advice_unsatisfiable'
                elif not u_left:
                    u_cat, u_sub = 'decided', None
                else:
                    u_cat = 'post_remediation_exposure'
                    u_sub = ('target_advisory_persists' if u_hits
                             else 'cross_advisory_residual_exposure')
                union_counts[arm][u_cat] += 1
                if u_sub:
                    union_subs[arm][u_sub] += 1
                base['union_baseline'] = {
                    'category': u_cat, 'subclass': u_sub,
                    'residual_range_count': len(u_left),
                    'residual_includes_this_query': u_hits}
                # Protocol order: conflict is asked before exposure. The two orders
                # agree - a recommendation that leaves no residue is itself a candidate
                # that clears the package, so `decided` can never also be a conflict -
                # but the code follows the table so a reader does not have to prove that.
                if not satisfiable[(arm, package)]:
                    # Nothing this arm recommends for this package clears every range
                    # its own fixes answer. NOTE the claim this does and does not
                    # support: npm keeps several versions of one package at different
                    # nesting paths, so this is NOT "a real lockfile cannot satisfy
                    # them" - it is "no single version candidate clears the modelled
                    # ranges" (R36a).
                    entry = {**base, 'category': 'conflict',
                             'subclass': 'package_advice_unsatisfiable',
                             'candidates_that_would_clear': []}
                elif not left:
                    entry = {**base, 'category': 'decided', 'subclass': None}
                else:
                    entry = {
                        **base,
                        'category': 'post_remediation_exposure',
                        'subclass': ('target_advisory_persists' if hits_target
                                     else 'cross_advisory_residual_exposure'),
                        'candidates_that_would_clear':
                            satisfiable[(arm, package)][:8],
                    }
            else:
                raise ValueError(f'unmapped H2 outcome {outcome!r}')

            row['by_arm'][arm] = entry
            counts[arm][entry['category']] += 1
            if entry.get('subclass'):
                subs[arm][entry['subclass']] += 1
        rows.append(row)

    doc = assemble(ledger, scores, results, rows, counts, subs, not_comparable,
                   declines, union_counts, union_subs)
    doc['residual_range_index'] = residual_index(ents, refs)
    doc['residual_range_index_note'] = (
        'Provenance for every range named in a row residual_ranges, keyed '
        '"arm|package|range". Held once rather than repeated per row; complete, not '
        'sampled. `records` is present where the ledger pins the range to a record '
        'unambiguously - that is, where the arm cites exactly one range for a query.')
    return doc


def target_resolved(counts, subs, arm):
    """decided + cross_advisory_residual_exposure - this query's own advisory cleared.

    Written out by the artefact because a number the reader has to add up is a number
    that eventually gets added up wrong.
    """
    return counts[arm]['decided'] + subs[arm].get(
        'cross_advisory_residual_exposure', 0)


def bootstrap(rows, arm, predicate, eligible):
    """Entity-clustered percentile interval. Descriptive precision, NOT a test."""
    clusters = defaultdict(list)
    for r in rows:
        cell = r['by_arm'][arm]
        if cell.get('category') is None:
            continue
        clusters[r['entity_id']].append(bool(predicate(cell)))
    keys = sorted(clusters)
    if not keys or not eligible:
        return None
    rng = random.Random(BOOTSTRAP_SEED)
    draws = []
    for _ in range(BOOTSTRAP_DRAWS):
        hit = tot = 0
        for _ in range(len(keys)):
            for v in clusters[keys[rng.randrange(len(keys))]]:
                tot += 1
                hit += v
        draws.append(hit / tot if tot else 0.0)
    draws.sort()
    lo = draws[int(0.025 * (len(draws) - 1))]
    hi = draws[int(0.975 * (len(draws) - 1))]
    return {'lower': round(lo, 6), 'upper': round(hi, 6),
            'draws': BOOTSTRAP_DRAWS, 'seed': BOOTSTRAP_SEED,
            'clustered_on': 'entity_id',
            'note': 'Descriptive precision only. Not a hypothesis test.'}


def paired_conversion(rows):
    """Unified against each single source, on the queries BOTH can be asked.

    R36a: the artefact reported each arm on its own denominator (2,902 / 2,336 / 2,361
    / 2,927) and then invited a comparison of the magnitudes. That is the cross-
    denominator error H2 already records for its three paired comparisons. Every
    difference quoted between two arms has to come from here.
    """
    out = {}
    for src in SOURCES:
        pair = [r for r in rows
                if r['by_arm'][src].get('category') is not None
                and r['by_arm']['unified'].get('category') is not None]
        table = {c: {'source': 0, 'unified': 0, 'delta': 0} for c in CATEGORIES}
        for r in pair:
            table[r['by_arm'][src]['category']]['source'] += 1
            table[r['by_arm']['unified']['category']]['unified'] += 1
        for c in CATEGORIES:
            table[c]['delta'] = table[c]['unified'] - table[c]['source']
        # Where the two arms land differently, and how.
        moves = defaultdict(int)
        for r in pair:
            a, b = r['by_arm'][src]['category'], r['by_arm']['unified']['category']
            if a != b:
                moves[f'{a} -> {b}'] += 1
        out[f'unified|{src}'] = {
            'paired_queries': len(pair),
            'counts': table,
            'transitions': dict(sorted(moves.items())),
            'note': ('Both arms answerable on every one of these queries. Differences '
                     'quoted anywhere else in this artefact are on unequal bases and '
                     'are not comparisons.'),
        }
    return out


def assemble(ledger, scores, results, rows, counts, subs, not_comparable,
             declines, union_counts, union_subs):
    # The most common package, and the same counts without it. The distribution is
    # steep enough that omitting this turns the round into a description of one package.
    freq = defaultdict(set)
    for q in ledger['queries']:
        freq[q['package']].add(q['entity_id'])
    largest = max(freq, key=lambda p: (len(freq[p]), p))

    without = {a: {c: 0 for c in CATEGORIES} for a in ARMS}
    without_subs = {a: defaultdict(int) for a in ARMS}
    for r in rows:
        if r['package'] == largest:
            continue
        for arm in ARMS:
            cell = r['by_arm'][arm]
            if cell.get('category') is None:
                continue
            without[arm][cell['category']] += 1
            if cell.get('subclass'):
                without_subs[arm][cell['subclass']] += 1

    # Package level: package NAMES merged across the whole cohort. This is NOT a real
    # dependency tree and R36b removed the "closer to a real lockfile scan" claim - a
    # real tree can carry several versions of one package at different nesting paths.
    # A package counts as clean only if EVERY query on it is decided. There is
    # deliberately no severity ranking of the non-decided categories: ordering "cannot
    # decide" against "decided but still exposed" would be my opinion, not a
    # measurement, and the first version of this block silently reported zero conflicts
    # because such an order swallowed them.
    seen = {a: defaultdict(set) for a in ARMS}
    excluded = {a: defaultdict(set) for a in ARMS}
    for r in rows:
        for arm in ARMS:
            cell = r['by_arm'][arm]
            c = cell.get('category')
            if c is not None:
                seen[arm][r['package']].add(c)
            else:
                excluded[arm][r['package']].add(cell.get('disposition'))
    per_package = {}
    for arm in ARMS:
        pkgs = seen[arm]
        clean = sum(1 for cats in pkgs.values() if cats == {'decided'})
        reasons = {c: sum(1 for cats in pkgs.values()
                          if c in cats and cats != {'decided'})
                   for c in CATEGORIES if c != 'decided'}
        # R36b: the old name `packages_with_any_query` was wrong - it counted packages
        # with at least one EVALUABLE category, so it read 830/741/747/831 against a
        # cohort of 831 and looked like a package census. Packages carrying only
        # not_comparable or declines_action rows are now named and counted apart.
        left_out = {pkg: sorted(d for d in ds if d)
                    for pkg, ds in excluded[arm].items() if pkg not in pkgs}
        by_disposition = defaultdict(int)
        for ds in left_out.values():
            for d in ds:
                by_disposition[d] += 1
        per_package[arm] = {
            'packages_with_evaluable_post_remediation_category': len(pkgs),
            'clean_after_remediation': clean,
            'not_clean': len(pkgs) - clean,
            'not_clean_carrying': reasons,
            'packages_without_evaluable_category': len(left_out),
            'packages_without_evaluable_category_by_disposition':
                dict(sorted(by_disposition.items())),
            'packages_without_evaluable_category_examples':
                sorted(left_out)[:5],
        }

    evaluated = {a: sum(counts[a].values()) for a in ARMS}
    intervals = {}
    for arm in ARMS:
        intervals[arm] = {
            'decided': bootstrap(rows, arm, lambda c: c['category'] == 'decided',
                                 evaluated[arm]),
            'target_advisory_resolved': bootstrap(
                rows, arm,
                lambda c: (c['category'] == 'decided'
                           or c.get('subclass') == 'cross_advisory_residual_exposure'),
                evaluated[arm]),
        }

    return {
        'schema': SCHEMA,
        'protocol_version': PROTOCOL,
        'note': ('Offline semver counterfactual replay: which declared ranges would '
                 'still contain the version each arm names. NOTHING WAS INSTALLED and '
                 'no scanner was run - that is R37, live GitHub Actions validation. '
                 'Counts and descriptive intervals only: no p-value, no correction, no '
                 'verdict. H2 is read, never recomputed.'),
        'inputs_sha256': {
            'h2_query_ledger.json': sha(QUERIES),
            'h2_scores.json': sha(SCORES),
            'h2_results.json': sha(RESULTS),
            'H2_RANGE_DECISIONS.json': sha(DECISIONS),
        },
        # Which rules produced this, which code computed it, which gate passed it.
        # No git commit on purpose: an artefact is always generated BEFORE the commit
        # that carries it, so the hash written in could only ever be the parent's
        # (R23b-F5 deleted `source_commit` for exactly that), and embedding HEAD would
        # break `--check` the moment anything is committed. Content hashes do not lag.
        'provenance_sha256': {
            'protocol': sha(PROTOCOL_DOC),
            'generator': sha(pathlib.Path(__file__)),
            'gate': sha(GATE),
            'note': ('Content hashes, not a commit. The gate re-reads all three from '
                     'disk and fails if any has moved.'),
        },
        'h2_reference': {
            'h2_supported': results['decision']['h2_supported'],
            'protocol_version': scores['protocol_version'],
            'note': ('Quoted from the sealed artefact. R36 neither recomputes nor '
                     'revisits it.'),
        },
        'rescan_baseline': {
            'primary': "the arm's own declared ranges for that package",
            'secondary_reported_separately': 'the union of all three sources',
            'unified_note': ('The unified arm IS the union, so its two baselines '
                             'coincide by construction - not a second confirmation.'),
        },
        'denominator': {
            'queries': len(ledger['queries']),
            'excluded_before_endpoint': len(ledger.get('skipped', [])),
            'evaluated_per_arm': evaluated,
            'not_comparable_per_arm': not_comparable,
            'note': ('The frozen H2 denominator, unchanged. Skipped pairs carry no '
                     'constructable query and enter nothing.'),
            'cross_arm_warning': (
                'The four arms do NOT share a denominator: the no-CVE stratum is keyed '
                'to one source, so the others have no question to answer there. Rates '
                'and intervals below are each on their own base and comparing their '
                'magnitudes across arms is undefined - the same limit H2 records for '
                'its three paired comparisons. Compare counts, or compare arms only '
                'on queries both can be asked.'),
        },
        'counts': counts,
        'subclasses': {a: dict(sorted(subs[a].items())) for a in ARMS},
        'declines_action': {
            'counts': declines,
            'note': ('A decision that no action is needed - the arm places the '
                     'installed version outside every range it declares. Reported '
                     'apart and folded into no rate, because "I think you are fine" '
                     'and "I do not know" are different answers.'),
        },
        'secondary_union_baseline': {
            'counts': union_counts,
            'subclasses': {a: dict(sorted(union_subs[a].items())) for a in ARMS},
            'note': ('The same classification re-scanned against every range the '
                     'corpus knows for that package, not only the arm own. Reported '
                     'beside the primary reading, never mixed into it. Unified is the '
                     'union by construction, so its two readings coincide.'),
        },
        'paired_conversion': paired_conversion(rows),
        'target_advisory_resolved': {a: target_resolved(counts, subs, a)
                                     for a in ARMS},
        'intervals': intervals,
        'per_package': {
            'packages_in_cohort': len(freq),
            'rule': ('Package NAMES merged across the whole cohort - not a real '
                     'dependency tree, and not a lockfile. A package counts as clean '
                     'only if every query on it is decided. The not-clean reasons '
                     'overlap by construction - one package can carry several - so '
                     'they do not sum to `not_clean`. The per-arm denominator is '
                     'packages with at least one evaluable category, which is why it '
                     'differs by arm and is smaller than the cohort.'),
            'counts': per_package,
        },
        'concentration': {
            'largest_package': largest,
            'entities_on_it': len(freq[largest]),
            'share_of_queries': round(
                sum(1 for r in rows if r['package'] == largest) / len(rows), 6),
            'counts_excluding_largest': without,
            'subclasses_excluding_largest': {a: dict(sorted(without_subs[a].items()))
                                             for a in ARMS},
        },
        'decisions': rows,
    }


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def serialise(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True)
            .replace('\r\n', '\n') + '\n').encode('utf-8')


# ----------------------------------------------------------------------- self-test

def self_test():
    """Synthetic shapes, so the classifier is exercised without the real corpus."""
    ok = True

    def check(label, cond):
        nonlocal ok
        ok = ok and cond
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")

    # A miss in the oracle must raise, never read as "not in range".
    try:
        NR.satisfies('9.9.9', '>=0.0.0 <0.0.1-nonexistent')
        raised = False
    except NR.LedgerMiss:
        raised = True
    check('an undecided (version, range) pair raises instead of reading as clean',
          raised)

    # A synthetic "<x.y.z means strictly below" oracle, only for these shapes.
    def toy(version, range_string):
        assert range_string.startswith('<'), range_string
        want = [int(p) for p in range_string[1:].split('.')]
        have = [int(p) for p in version.split('.')]
        return have < want

    both = {'<2.0.0', '<3.0.0'}
    left, target = residual('2.0.0', both, {'<2.0.0'}, satisfies=toy)
    check('a fix outside its own range but inside another is reported as residual',
          left == ['<3.0.0'])
    check('and is not attributed to this query own advisory', target is False)

    left2, target2 = residual('1.5.0', both, {'<2.0.0'}, satisfies=toy)
    check('a fix still inside its own range flags the target advisory',
          target2 is True and left2 == ['<2.0.0', '<3.0.0'])

    clean, target3 = residual('3.0.0', both, {'<2.0.0'}, satisfies=toy)
    check('a fix outside every range leaves nothing residual',
          clean == [] and target3 is False)

    # An unparseable version satisfies nothing, which is not the same as clearing.
    check('npm rejects a version with a leading zero',
          NR.parsed('2026.03.28').get('valid') is False)
    check('and that version satisfies nothing, so it must not count as a remedy',
          NR.satisfies('2026.03.28', '>=0.0.0') is False
          and NR.satisfies('2026.4.14', '>=0.0.0') is True)

    ents = {('ghsa', 'p', '<2.0.0'): {'E1', 'E9'}}
    refs = {('ghsa', 'p', '<2.0.0'): {('ghsa:GHSA-x', '/v/0/range')}}
    idx = residual_index(ents, refs)
    check('the provenance index holds every declaring entity, not a sample',
          idx['ghsa|p|<2.0.0']['declared_by_entities'] == ['E1', 'E9'])
    check('and carries the record it can pin',
          idx['ghsa|p|<2.0.0']['records'][0]['record_ref'] == 'ghsa:GHSA-x')

    counts = {'ghsa': {'decided': 3, 'undecidable': 1, 'conflict': 0,
                       'post_remediation_exposure': 5}}
    subs = {'ghsa': {'cross_advisory_residual_exposure': 5}}
    check('target_advisory_resolved = decided + cross-advisory residual',
          target_resolved(counts, subs, 'ghsa') == 8)

    check('every H2 outcome has a declared R36 landing',
          set(UNDECIDABLE_FROM) | {DECLINES_ACTION_FROM, 'ambiguous_or_conflicting',
                                   'success'} == set(SC.OUTCOMES))
    check('declines_action is NOT one of the undecidable subclasses',
          DECLINES_ACTION_FROM not in UNDECIDABLE_FROM
          and 'declines_action' not in UNDECIDABLE_FROM.values())

    print(f"H2 CI/CD SELF-TEST: {'PASS' if ok else 'FAIL'}")
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
        on_disk = OUT.read_bytes()
        same = on_disk == data
        print(f"{'IDENTICAL' if same else 'DIFFERS'}: sha256 "
              f"{hashlib.sha256(data).hexdigest()[:16]}...")
        return 0 if same else 1
    OUT.write_bytes(data)
    for arm in ARMS:
        c = doc['counts'][arm]
        s = doc['subclasses'][arm]
        print(f"  {arm:8} decided {c['decided']:5}  undecidable {c['undecidable']:5}"
              f"  conflict {c['conflict']:5}"
              f"  post-remediation {c['post_remediation_exposure']:5}"
              f"  (target persists {s.get('target_advisory_persists', 0)},"
              f" cross-advisory {s.get('cross_advisory_residual_exposure', 0)})")
    print(f"  largest package {doc['concentration']['largest_package']!r} = "
          f"{doc['concentration']['share_of_queries']:.1%} of queries")
    print(f'{OUT.name}: sha256 {hashlib.sha256(data).hexdigest()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
