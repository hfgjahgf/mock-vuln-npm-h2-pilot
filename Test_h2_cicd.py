"""Does the CI/CD artefact say what the frozen ledger actually supports?

WHY THIS EXISTS SEPARATELY FROM `derive_h2_cicd.py --check`

  That flag calls the same `build()` again and proves one program reproduces its own
  output. It says nothing about whether the categories, the denominators, or the claim
  that H2 was left alone are right. This recomputes every category from the frozen query
  ledger and the frozen npm oracle, with the constants RESTATED here rather than imported
  from the module under test (R25b-Fa) and with its own reading of what each arm says.

    python Test_h2_cicd.py [--json]
    python Test_h2_cicd.py --self-test

Protocol: schemas/H2_CICD_PROTOCOL.md (h2-cicd-protocol-2).
"""
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import npm_range_h2 as NR

ROOT = Path(__file__).resolve().parent
QUERIES = ROOT / 'h2_query_ledger.json'
SCORES = ROOT / 'h2_scores.json'
RESULTS = ROOT / 'h2_results.json'
DECISIONS = ROOT / 'schemas' / 'H2_RANGE_DECISIONS.json'
ARTEFACT = ROOT / 'h2_cicd_decisions.json'
PROTOCOL_DOC = ROOT / 'schemas' / 'H2_CICD_PROTOCOL.md'

# Restated, never imported from derive_h2_cicd.
SOURCES = ('ghsa', 'nvd', 'osv')
ARMS = SOURCES + ('unified',)
CATEGORIES = ('decided', 'undecidable', 'conflict', 'post_remediation_exposure')
EXPECTED_SCHEMA = 'h2-cicd-decisions/2'
EXPECTED_PROTOCOL = 'h2-cicd-protocol-2'
GENERATOR = ROOT / 'derive_h2_cicd.py'
EXPECTED_COHORT_PACKAGES = 831
# Per arm: packages carrying at least one EVALUABLE category. Smaller than the
# cohort, and different per arm - which is exactly what the old field name hid.
EXPECTED_EVALUABLE_PACKAGES = {'ghsa': 830, 'nvd': 741, 'osv': 747,
                              'unified': 831}

EXPECTED_QUERIES = 2927
EXPECTED_SKIPPED = 139
EXPECTED_NOT_COMPARABLE = {'ghsa': 25, 'nvd': 591, 'osv': 566, 'unified': 0}
# H2's own success counts. Every one of them must land in a category that ACTED - a
# query H2 called a success cannot be undecidable here.
EXPECTED_H2_SUCCESS = {'ghsa': 2523, 'nvd': 0, 'osv': 126, 'unified': 2552}
EXPECTED_LARGEST_PACKAGE = 'openclaw'
EXPECTED_LARGEST_ENTITIES = 745

# The sealed H2 result. R36 must leave it exactly where R35a left it.
FROZEN_H2_RESULTS_SHA256 = (
    'a69b50b78167885cd80ce43af77cdf71ca1aacfc382ccc175aef2877bef0f04e')
EXPECTED_H2_SUPPORTED = False

UNDECIDABLE_FROM = {
    'not_covered': 'not_covered',
    'covered_but_no_package': 'covered_but_no_package',
    'package_but_no_fix': 'package_but_no_fix',
    'untraceable_or_invalid': 'untraceable_or_invalid',
}
# Reported apart, in no rate - a decision that was made, not an absence of one.
DECLINES_ACTION_FROM = 'range_disagreement'
EXPECTED_DECLINES = {'ghsa': 5, 'nvd': 1, 'osv': 0, 'unified': 0}
# The secondary reading of §3, recomputed here. R36a: the protocol promised it and the
# artefact carried only a sentence. OSV moves 34 rows, so it is not decoration.
FROZEN_UNION = {
    'ghsa': {'decided': 929, 'post_remediation_exposure': 1594},
    'nvd': {'decided': 0, 'post_remediation_exposure': 0},
    'osv': {'decided': 55, 'post_remediation_exposure': 71},
    'unified': {'decided': 939, 'post_remediation_exposure': 1613},
}

# Anything that would make this a second inference. `h2_supported` is allowed only where
# the artefact quotes the sealed result.
FORBIDDEN_KEY = re.compile(
    r'p_value|adjusted|holm|alpha|significan|permutation|_supported|verdict',
    re.IGNORECASE)
QUOTE_PATH = ('h2_reference',)


def view(query, arm):
    """What this arm says about this query - the gate's own reading of the ledger."""
    if arm != 'unified':
        b = query['by_source'][arm]
        return (list(b['declares_ranges']),
                list(b['branch_fix_stated_for_containing_range']))
    ranges, fixes = [], []
    for s in SOURCES:
        ranges += query['by_source'][s]['declares_ranges']
        fixes += query['by_source'][s]['branch_fix_stated_for_containing_range']
    return ranges, fixes


def containing(query, arm):
    """The declared ranges that actually contain the installed version."""
    if arm != 'unified':
        return list(query['by_source'][arm]['ranges_containing_installed'])
    out = []
    for s in SOURCES:
        out += query['by_source'][s]['ranges_containing_installed']
    return out


def recompute(ledger, scores):
    """Every category, rebuilt from the ledger and the frozen oracle."""
    known = {a: defaultdict(set) for a in ARMS}
    stated = {a: defaultdict(set) for a in ARMS}
    answered = {a: defaultdict(set) for a in ARMS}
    union_known = defaultdict(set)
    for q in ledger['queries']:
        union_known[q['package']].update(q['affected_ranges'])
    for q in ledger['queries']:
        for arm in ARMS:
            r, f = view(q, arm)
            known[arm][q['package']].update(r)
            stated[arm][q['package']].update(f)
            if f:
                answered[arm][q['package']].update(containing(q, arm))

    def residue(fix, ranges):
        # LedgerMiss propagates: a lookup the oracle never decided must never be read
        # as "not in range", which is the reading that inflates `decided`.
        return [r for r in sorted(ranges) if NR.satisfies(fix, r)]

    # Protocol §4.2: the conflict test runs against the ranges the arm actually STATED
    # A FIX FOR. An advisory with no fix is absent advice, not contradicting advice.
    # And only a version npm would accept can clear anything: an unparseable string
    # satisfies no range at all and would otherwise read as the one clean candidate.
    satisfiable = {}
    for arm in ARMS:
        for pkg, fixes in stated[arm].items():
            satisfiable[(arm, pkg)] = [f for f in sorted(fixes)
                                       if NR.parsed(f).get('valid')
                                       and not residue(f, answered[arm][pkg])]

    by_key = {(r['entity_id'], r['package']): r for r in scores['scores']}
    out = {}
    for q in ledger['queries']:
        scored = by_key[(q['entity_id'], q['package'])]
        for arm in ARMS:
            cell = scored['by_arm'][arm]
            key = (q['entity_id'], q['package'], arm)
            if not cell.get('comparable'):
                out[key] = (None, None, None, None, None, None)
                continue
            outcome = cell['outcome']
            if outcome == DECLINES_ACTION_FROM:
                out[key] = (None, 'declines_action', None, None, None, None)
                continue
            if outcome in UNDECIDABLE_FROM:
                out[key] = ('undecidable', UNDECIDABLE_FROM[outcome], [], False,
                            'undecidable', UNDECIDABLE_FROM[outcome])
            elif outcome == 'ambiguous_or_conflicting':
                out[key] = ('conflict', 'within_query', [], False, 'conflict',
                            'within_query')
            elif outcome == 'success':
                pkg = q['package']
                own, fixes = view(q, arm)
                recommended = sorted(set(fixes))[0]
                left = residue(recommended, known[arm][pkg])
                hits = any(r in set(own) for r in left)
                u_left = residue(recommended, union_known[pkg])
                u_hits = any(r in set(own) for r in u_left)
                if not satisfiable[(arm, pkg)]:
                    cat, sub = 'conflict', 'package_advice_unsatisfiable'
                    u_cat, u_sub = 'conflict', 'package_advice_unsatisfiable'
                else:
                    cat = 'decided' if not left else 'post_remediation_exposure'
                    sub = (None if not left else
                           ('target_advisory_persists' if hits
                            else 'cross_advisory_residual_exposure'))
                    u_cat = 'decided' if not u_left else 'post_remediation_exposure'
                    u_sub = (None if not u_left else
                             ('target_advisory_persists' if u_hits
                              else 'cross_advisory_residual_exposure'))
                out[key] = (cat, sub, left, hits, u_cat, u_sub)
            else:
                out[key] = ('UNMAPPED', outcome, [], False, None, None)
    return out


# ---------------------------------------------------------------------------

def check_denominator_unchanged(art, ledger):
    v = []
    d = art['denominator']
    if d['queries'] != EXPECTED_QUERIES or len(ledger['queries']) != EXPECTED_QUERIES:
        v.append(f'the denominator is {d["queries"]}, the frozen ledger has '
                 f'{len(ledger["queries"])}, {EXPECTED_QUERIES} expected')
    if d['excluded_before_endpoint'] != EXPECTED_SKIPPED:
        v.append(f'excluded_before_endpoint {d["excluded_before_endpoint"]}, '
                 f'{EXPECTED_SKIPPED} expected')
    for arm in ARMS:
        total = sum(art['counts'][arm].values())
        nc = art['denominator']['not_comparable_per_arm'][arm]
        # Three dispositions, not two: a query is categorised, or it cannot be asked,
        # or the arm decided no action was needed. R36a added the third, and every
        # query still has to land in exactly one of them.
        dec = (art.get('declines_action') or {}).get('counts', {}).get(arm, 0)
        if nc != EXPECTED_NOT_COMPARABLE[arm]:
            v.append(f'{arm}: not_comparable {nc}, {EXPECTED_NOT_COMPARABLE[arm]} '
                     f'expected')
        if total + nc + dec != EXPECTED_QUERIES:
            v.append(f'{arm}: {total} categorised + {nc} not comparable + {dec} '
                     f'declines != {EXPECTED_QUERIES}')
        if art['denominator']['evaluated_per_arm'][arm] != total:
            v.append(f'{arm}: evaluated_per_arm disagrees with its own counts')
    return {'violations': v, 'ok': not v}


def check_oracle_coverage(ledger):
    """Every (fix, range) the classification needs must already be decided offline."""
    v = []
    known, stated = defaultdict(set), defaultdict(set)
    for q in ledger['queries']:
        for arm in ARMS:
            r, f = view(q, arm)
            known[(arm, q['package'])].update(r)
            stated[(arm, q['package'])].update(f)
    lookups = missing = 0
    for key, fixes in stated.items():
        for fix in fixes:
            for rng in known[key]:
                lookups += 1
                try:
                    NR.satisfies(fix, rng)
                except NR.LedgerMiss:
                    missing += 1
    if missing:
        v.append(f'{missing} of {lookups} membership lookups were never decided by the '
                 f'offline oracle - reading them as "not in range" would inflate decided')
    # And the miss must raise rather than answer. A gate that only counts misses would
    # pass on the day the function starts returning False for unknown pairs.
    try:
        NR.satisfies('9.9.9', '<0.0.1-no-such-range')
        v.append('an undecided (version, range) pair answered instead of raising')
    except NR.LedgerMiss:
        pass
    return {'lookups': lookups, 'missing': missing, 'violations': v, 'ok': not v}


def check_categories_recomputed(art, truth):
    v = []
    seen = 0
    for row in art['decisions']:
        for arm in ARMS:
            cell = row['by_arm'][arm]
            key = (row['entity_id'], row['package'], arm)
            want_cat, want_sub, want_left, want_hits, _u, _us = truth[key]
            got_cat = cell.get('category')
            if got_cat != want_cat:
                v.append(f'{row["entity_id"]}/{row["package"]}/{arm}: recorded '
                         f'{got_cat}, recomputed {want_cat}')
            elif got_cat is not None and cell.get('subclass') != want_sub:
                v.append(f'{row["entity_id"]}/{row["package"]}/{arm}: subclass '
                         f'{cell.get("subclass")}, recomputed {want_sub}')
            if got_cat is None:
                seen += 1
                continue
            # The residue fields exist only where a version was actually installed.
            # Emitting a zero for a row that never had a recommendation would read as
            # "clean", so their ABSENCE is checked too, not merely tolerated.
            if cell.get('recommended_version') is None:
                for field in ('residual_ranges', 'residual_range_count',
                              'residual_includes_this_query'):
                    if field in cell:
                        v.append(f'{row["entity_id"]}/{arm}: {field} on a row with no '
                                 f'recommendation - a zero here reads as clean')
                seen += 1
                continue
            # A category is a claim about the residue; the residue has to back it, and
            # it has to be the residue this gate recomputed - not merely non-empty.
            if (cell.get('residual_ranges') or []) != want_left:
                v.append(f'{row["entity_id"]}/{arm}: residual ranges recorded '
                         f'{len(cell.get("residual_ranges") or [])}, recomputed '
                         f'{len(want_left)}')
            if cell.get('residual_range_count') != len(want_left):
                v.append(f'{row["entity_id"]}/{arm}: residual_range_count disagrees '
                         f'with its own list')
            if bool(cell.get('residual_includes_this_query')) != bool(want_hits):
                v.append(f'{row["entity_id"]}/{arm}: residual_includes_this_query '
                         f'recorded {cell.get("residual_includes_this_query")}, '
                         f'recomputed {want_hits}')
            if got_cat == 'decided' and want_left:
                v.append(f'{row["entity_id"]}/{arm}: decided, yet ranges still hit it')
            if got_cat == 'post_remediation_exposure' and not want_left:
                v.append(f'{row["entity_id"]}/{arm}: exposure claimed with no residual '
                         f'range behind it')
            seen += 1
            if len(v) > 12:
                return {'violations': v[:12] + ['...'], 'ok': False}
    counts = {a: {c: 0 for c in CATEGORIES} for a in ARMS}
    subs = {a: defaultdict(int) for a in ARMS}
    for key, (cat, sub, _left, _hits, _u, _us) in truth.items():
        if cat is None:
            continue
        counts[key[2]][cat] += 1
        if sub:
            subs[key[2]][sub] += 1
    for arm in ARMS:
        if art['counts'][arm] != counts[arm]:
            v.append(f'{arm}: counts recorded {art["counts"][arm]}, recomputed '
                     f'{counts[arm]}')
        if art['subclasses'][arm] != dict(sorted(subs[arm].items())):
            v.append(f'{arm}: subclass counts disagree with the recomputed ones')
    return {'cells': seen, 'violations': v, 'ok': not v}


def check_subclass_split(art, truth):
    v = []
    for arm in ARMS:
        subs = art['subclasses'][arm]
        exposure = art['counts'][arm]['post_remediation_exposure']
        pair = (subs.get('target_advisory_persists', 0)
                + subs.get('cross_advisory_residual_exposure', 0))
        if pair != exposure:
            v.append(f'{arm}: the two exposure subclasses sum to {pair}, the category '
                     f'holds {exposure}')
        want = art['counts'][arm]['decided'] + subs.get(
            'cross_advisory_residual_exposure', 0)
        if art['target_advisory_resolved'][arm] != want:
            v.append(f'{arm}: target_advisory_resolved recorded '
                     f'{art["target_advisory_resolved"][arm]}, recomputed {want}')
    # target_advisory_persists may only be claimed when the residue is this query's own.
    # Read against the gate's own recomputation, not the row's self-description: a row
    # that mislabels its subclass usually mislabels the flag next to it the same way.
    index = art.get('residual_range_index') or {}
    for row in art['decisions']:
        for arm in ARMS:
            cell = row['by_arm'][arm]
            sub = cell.get('subclass')
            if sub not in ('target_advisory_persists',
                           'cross_advisory_residual_exposure'):
                continue
            _cat, _sub, _left, hits, _u, _us = truth[
                (row['entity_id'], row['package'], arm)]
            if (sub == 'target_advisory_persists') != bool(hits):
                v.append(f'{row["entity_id"]}/{arm}: labelled {sub}, but the residue '
                         f'{"does" if hits else "does not"} include this query own range')
            for rng in cell.get('residual_ranges') or []:
                if f'{arm}|{row["package"]}|{rng}' not in index:
                    v.append(f'{row["entity_id"]}/{arm}: residual range {rng!r} has no '
                             f'entry in the provenance index')
    return {'violations': v[:12], 'ok': not v}


def check_clearing_candidates(art, ledger):
    """A version offered as the one that would clear the package must be a real version.

    Stated as its own invariant rather than as a by-product of the recomputation: an
    unparseable string satisfies no range, so both the derivation and this gate would
    call it clean if both merely re-ran the same reasoning. That is how R35a's halved
    fraction survived - the gate had been written from the same thought.
    """
    v = []
    answered = defaultdict(set)
    for q in ledger['queries']:
        for arm in ARMS:
            if view(q, arm)[1]:
                answered[(arm, q['package'])].update(containing(q, arm))
    checked = 0
    for row in art['decisions']:
        for arm in ARMS:
            for cand in row['by_arm'][arm].get('candidates_that_would_clear') or []:
                checked += 1
                if not NR.parsed(cand).get('valid'):
                    v.append(f'{row["package"]}/{arm}: {cand!r} is offered as a version '
                             f'that clears the package, but npm cannot parse it - it '
                             f'satisfies nothing, which is not the same as clearing')
                elif any(NR.satisfies(cand, r)
                         for r in answered[(arm, row['package'])]):
                    v.append(f'{row["package"]}/{arm}: {cand!r} is offered as clearing '
                             f'the arm own fixed ranges while one still contains it')
                if len(v) > 8:
                    return {'violations': v[:8] + ['...'], 'ok': False}
    return {'candidates_checked': checked, 'violations': v, 'ok': not v}


def check_declines_action_apart(art, truth):
    """"I think you are fine" must not be counted as "I do not know".

    R36a: the protocol said declines_action is reported apart and folded into no rate;
    the code had it inside `undecidable`, which is that folding.
    """
    v = []
    got = (art.get('declines_action') or {}).get('counts')
    if got != EXPECTED_DECLINES:
        v.append(f'declines_action counts {got}, {EXPECTED_DECLINES} expected')
    recomputed = {a: 0 for a in ARMS}
    for (_e, _p, arm), tup in truth.items():
        if tup[1] == 'declines_action':
            recomputed[arm] += 1
    if got != recomputed:
        v.append(f'declines_action recorded {got}, recomputed {recomputed}')
    for arm in ARMS:
        if 'declines_action' in art['subclasses'][arm]:
            v.append(f'{arm}: declines_action is still a subclass of a category')
    for row in art['decisions']:
        for arm in ARMS:
            cell = row['by_arm'][arm]
            if cell.get('disposition') == 'declines_action' and cell.get('category'):
                v.append(f'{row["entity_id"]}/{arm}: declines_action carries a category')
    return {'violations': v[:8], 'ok': not v}


def check_union_baseline(art, truth):
    """The secondary reading the protocol promised, recomputed rather than asserted."""
    v = []
    blk = art.get('secondary_union_baseline') or {}
    got = blk.get('counts')
    if not got:
        return {'violations': ['the union baseline is not emitted at all'], 'ok': False}
    recomputed = {a: {c: 0 for c in CATEGORIES} for a in ARMS}
    for (_e, _p, arm), tup in truth.items():
        if tup[4]:
            recomputed[arm][tup[4]] += 1
    # R36b: the subclasses were emitted and never checked. A top-level count can be
    # right while the split under it is wrong, and the split is what the reading rests on.
    sub_recomputed = {a: defaultdict(int) for a in ARMS}
    for (_e, _p, arm), tup in truth.items():
        if tup[5]:
            sub_recomputed[arm][tup[5]] += 1
    got_subs = blk.get('subclasses') or {}
    for arm in ARMS:
        if got[arm] != recomputed[arm]:
            v.append(f'{arm}: union counts recorded {got[arm]}, recomputed '
                     f'{recomputed[arm]}')
        want_sub = dict(sorted(sub_recomputed[arm].items()))
        if got_subs.get(arm) != want_sub:
            v.append(f'{arm}: union subclasses recorded {got_subs.get(arm)}, '
                     f'recomputed {want_sub}')
        if sum(want_sub.values()) > sum(recomputed[arm].values()):
            v.append(f'{arm}: more union subclass rows than union rows')
        for field, want in FROZEN_UNION[arm].items():
            if got[arm][field] != want:
                v.append(f'{arm}: union {field} is {got[arm][field]}, {want} frozen')
        if sum(got[arm].values()) != sum(art['counts'][arm].values()):
            v.append(f'{arm}: the two readings cover different row counts')
    # Unified IS the union, so the two readings must coincide for it - by construction,
    # which is why it is checked rather than assumed.
    if got['unified'] != art['counts']['unified']:
        v.append('unified: its own and union readings differ, which cannot happen')
    return {'violations': v[:8], 'ok': not v}


def check_paired_conversion(art):
    """Every cross-arm difference must come from queries BOTH arms can be asked."""
    v = []
    blk = art.get('paired_conversion') or {}
    if set(blk) != {f'unified|{s}' for s in SOURCES}:
        return {'violations': ['the paired conversion table is missing an arm'],
                'ok': False}
    for src in SOURCES:
        key = f'unified|{src}'
        pair = [r for r in art['decisions']
                if r['by_arm'][src].get('category') is not None
                and r['by_arm']['unified'].get('category') is not None]
        if blk[key]['paired_queries'] != len(pair):
            v.append(f'{key}: paired_queries {blk[key]["paired_queries"]}, '
                     f'recomputed {len(pair)}')
        want = {c: {'source': 0, 'unified': 0} for c in CATEGORIES}
        for r in pair:
            want[r['by_arm'][src]['category']]['source'] += 1
            want[r['by_arm']['unified']['category']]['unified'] += 1
        for c in CATEGORIES:
            cell = blk[key]['counts'][c]
            if (cell['source'], cell['unified']) != (want[c]['source'],
                                                     want[c]['unified']):
                v.append(f'{key}/{c}: recorded {cell["source"]}vs{cell["unified"]}, '
                         f'recomputed {want[c]["source"]}vs{want[c]["unified"]}')
            if cell['delta'] != cell['unified'] - cell['source']:
                v.append(f'{key}/{c}: delta does not follow from its own two counts')
        # R36b: the transition matrix was published and never recomputed. It is the
        # part a reader quotes ("integration moved N rows from X to Y"), so it is the
        # part that has to be re-derived rather than trusted.
        moves = Counter()
        for r in pair:
            a = r['by_arm'][src]['category']
            b = r['by_arm']['unified']['category']
            if a != b:
                moves[f'{a} -> {b}'] += 1
        if blk[key].get('transitions') != dict(sorted(moves.items())):
            v.append(f'{key}: transitions recorded {blk[key].get("transitions")}, '
                     f'recomputed {dict(sorted(moves.items()))}')
        # The matrix and the margins have to tell the same story.
        for c in CATEGORIES:
            inflow = sum(n for m, n in moves.items() if m.endswith(f'-> {c}'))
            outflow = sum(n for m, n in moves.items() if m.startswith(f'{c} ->'))
            cell = blk[key]['counts'][c]
            if cell['unified'] - cell['source'] != inflow - outflow:
                v.append(f'{key}/{c}: the transition matrix does not explain the '
                         f'margin delta {cell["delta"]}')
        # A paired table on an unequal base is the error this check exists to stop.
        if len(pair) > min(sum(art['counts'][src].values()),
                           sum(art['counts']['unified'].values())):
            v.append(f'{key}: the pair is larger than one of the arms own totals')
    return {'violations': v[:8], 'ok': not v}


def check_provenance_pinned(art):
    """Which rules, which code, which gate - re-read from disk, not taken on trust."""
    v = []
    blk = art.get('provenance_sha256') or {}
    for name, path in (('protocol', PROTOCOL_DOC), ('generator', GENERATOR),
                       ('gate', Path(__file__).resolve())):
        want = hashlib.sha256(path.read_bytes()).hexdigest()
        got = blk.get(name)
        if got != want:
            v.append(f'{name}: artefact declares {str(got)[:16]}..., disk has '
                     f'{want[:16]}...')
    if 'git' in json.dumps(blk).lower():
        v.append('a git commit was written into the artefact - it would lag by one '
                 'commit and break byte-reproduction (R23b-F5, protocol §11)')
    return {'violations': v, 'ok': not v}


def check_package_level_labelled(art, ledger):
    """The package-level denominator must be named for what it actually counts."""
    v = []
    blk = art.get('per_package') or {}
    cohort = len({q['package'] for q in ledger['queries']})
    if blk.get('packages_in_cohort') != cohort or cohort != EXPECTED_COHORT_PACKAGES:
        v.append(f'packages_in_cohort {blk.get("packages_in_cohort")}, recomputed '
                 f'{cohort}, {EXPECTED_COHORT_PACKAGES} expected')
    if 'lockfile' in (blk.get('rule') or '').lower() and 'not a lockfile' not in (
            blk.get('rule') or '').lower():
        v.append('the package-level rule still likens itself to a real lockfile')
    for arm in ARMS:
        cell = blk.get('counts', {}).get(arm, {})
        if 'packages_with_any_query' in cell:
            v.append(f'{arm}: still uses the name packages_with_any_query, which is '
                     f'not what it counts')
        got = cell.get('packages_with_evaluable_post_remediation_category')
        evaluable, left_out = set(), set()
        for r in art['decisions']:
            (evaluable if r['by_arm'][arm].get('category') is not None
             else left_out).add(r['package'])
        left_out -= evaluable
        if got != len(evaluable) or got != EXPECTED_EVALUABLE_PACKAGES[arm]:
            v.append(f'{arm}: evaluable packages {got}, recomputed {len(evaluable)}, '
                     f'{EXPECTED_EVALUABLE_PACKAGES[arm]} expected')
        if cell.get('packages_without_evaluable_category') != len(left_out):
            v.append(f'{arm}: excluded packages '
                     f'{cell.get("packages_without_evaluable_category")}, recomputed '
                     f'{len(left_out)}')
        if got is not None and got + len(left_out) != cohort:
            v.append(f'{arm}: {got} evaluable + {len(left_out)} excluded != {cohort}')
    return {'violations': v[:8], 'ok': not v}


def check_h2_linkage(art, scores):
    v = []
    acted = ('decided', 'conflict', 'post_remediation_exposure')
    tally = {a: 0 for a in ARMS}
    for row in art['decisions']:
        for arm in ARMS:
            if row['by_arm'][arm].get('category') in acted:
                tally[arm] += 1
    for arm in ARMS:
        if tally[arm] != EXPECTED_H2_SUCCESS[arm]:
            v.append(f'{arm}: {tally[arm]} queries were acted on, but H2 recorded '
                     f'{EXPECTED_H2_SUCCESS[arm]} successes')
        if scores['counts'][arm]['success'] != EXPECTED_H2_SUCCESS[arm]:
            v.append(f'{arm}: h2_scores.json on disk says '
                     f'{scores["counts"][arm]["success"]} successes')
    # Per query, not just in total: an H2 success must never be undecidable here.
    by_key = {(r['entity_id'], r['package']): r for r in scores['scores']}
    for row in art['decisions']:
        s = by_key[(row['entity_id'], row['package'])]
        for arm in ARMS:
            if s['by_arm'][arm].get('outcome') == 'success' and row['by_arm'][arm].get(
                    'category') == 'undecidable':
                v.append(f'{row["entity_id"]}/{arm}: H2 called this a success, R36 '
                         f'calls it undecidable')
    return {'violations': v[:12], 'ok': not v}


def check_h2_untouched(art):
    """R36 must leave H2 exactly where R35a sealed it - checked, not asserted."""
    v = []
    on_disk = hashlib.sha256(RESULTS.read_bytes()).hexdigest()
    if on_disk != FROZEN_H2_RESULTS_SHA256:
        v.append(f'h2_results.json is now {on_disk[:16]}..., R35a sealed '
                 f'{FROZEN_H2_RESULTS_SHA256[:16]}...')
    verdict = json.loads(RESULTS.read_text(encoding='utf-8'))['decision'][
        'h2_supported']
    if verdict is not EXPECTED_H2_SUPPORTED:
        v.append(f'h2_supported on disk reads {verdict}')
    if art['h2_reference']['h2_supported'] is not EXPECTED_H2_SUPPORTED:
        v.append('the artefact quotes a different verdict than the sealed one')
    for name, path in (('h2_query_ledger.json', QUERIES), ('h2_scores.json', SCORES),
                       ('h2_results.json', RESULTS),
                       ('H2_RANGE_DECISIONS.json', DECISIONS)):
        want = hashlib.sha256(path.read_bytes()).hexdigest()
        got = art['inputs_sha256'].get(name)
        if got != want:
            v.append(f'{name}: artefact declares {str(got)[:16]}..., disk has '
                     f'{want[:16]}...')
    return {'violations': v, 'ok': not v}


def check_concentration_disclosed(art, ledger):
    v = []
    freq = defaultdict(set)
    for q in ledger['queries']:
        freq[q['package']].add(q['entity_id'])
    largest = max(freq, key=lambda p: (len(freq[p]), p))
    c = art.get('concentration') or {}
    if c.get('largest_package') != largest or largest != EXPECTED_LARGEST_PACKAGE:
        v.append(f'largest package recorded {c.get("largest_package")}, recomputed '
                 f'{largest}, {EXPECTED_LARGEST_PACKAGE} expected')
    if c.get('entities_on_it') != EXPECTED_LARGEST_ENTITIES:
        v.append(f'entities on it {c.get("entities_on_it")}, '
                 f'{EXPECTED_LARGEST_ENTITIES} expected')
    excl = c.get('counts_excluding_largest') or {}
    if set(excl) != set(ARMS):
        v.append('the excluding-largest counts are missing an arm')
        return {'violations': v, 'ok': False}
    want = {a: {k: 0 for k in CATEGORIES} for a in ARMS}
    for row in art['decisions']:
        if row['package'] == largest:
            continue
        for arm in ARMS:
            cat = row['by_arm'][arm].get('category')
            if cat:
                want[arm][cat] += 1
    for arm in ARMS:
        if excl[arm] != want[arm]:
            v.append(f'{arm}: excluding-{largest} counts recorded {excl[arm]}, '
                     f'recomputed {want[arm]}')
    return {'violations': v, 'ok': not v}


def check_no_inference_emitted(art):
    """R36 is descriptive. A p-value here would make it a second vote on H2."""
    v = []

    def walk(node, path):
        if isinstance(node, dict):
            # Some maps are keyed BY DATA, not by field name - the provenance index is
            # keyed by npm range strings, and `>=2.10.0-alpha.3` is not a field called
            # alpha. Scanning those keys as if they were names produced 2,000 false
            # violations on the first run.
            data_keyed = path[:1] == ['residual_range_index']
            for k, sub in node.items():
                if (not data_keyed and FORBIDDEN_KEY.search(str(k))
                        and path[:1] != list(QUOTE_PATH)):
                    v.append(f'{"/".join(path + [str(k)])}: an inferential field')
                walk(sub, path + [str(k)])
        elif isinstance(node, list):
            for i, sub in enumerate(node[:200]):
                walk(sub, path + [str(i)])

    walk(art, [])
    if art.get('schema') != EXPECTED_SCHEMA:
        v.append(f'schema {art.get("schema")}, {EXPECTED_SCHEMA} expected')
    if art.get('protocol_version') != EXPECTED_PROTOCOL:
        v.append(f'protocol {art.get("protocol_version")}, {EXPECTED_PROTOCOL} expected')
    for arm in ARMS:
        for name, iv in (art.get('intervals') or {}).get(arm, {}).items():
            if iv and 'Not a hypothesis test' not in (iv.get('note') or ''):
                v.append(f'{arm}/{name}: an interval that does not say what it is not')
    return {'violations': v[:12], 'ok': not v}


DECLARED_BLOCK = re.compile(
    r'<!-- (terminology|selfref):start -->.*?<!-- \1:end -->', re.S)
# `/` is a SEPARATOR, not part of a token: "2,589/2,589" is two counts, and treating
# the slash as part of the token made the engine backtrack and report a phantom "589"
# that of course nothing could account for. `-` and `.` stay, so ISO dates and section
# numbers are still protected from being read as counts.
BARE_INTEGER = re.compile(r'(?<![\w.\-])(\d[\d,]*)(?![\w.\-])')


def check_protocol_declarations(ledger, text=None):
    """The protocol promises every count >= 100 in it can be recomputed. Enforce it.

    A rule the document states about itself and nothing checks is the shape R35a just
    finished removing from the results gate - a declared constant that no check reads.
    """
    v = []
    if text is None:
        if not PROTOCOL_DOC.exists():
            return {'violations': [f'{PROTOCOL_DOC.name} is missing'], 'ok': False}
        text = PROTOCOL_DOC.read_text(encoding='utf-8')
    body = DECLARED_BLOCK.sub('', text)
    skipped = len(text) - len(body)
    if not skipped:
        v.append('no declared block was skipped - the sentence stating the rule would '
                 'be judged by the rule it states')
    # What the frozen inputs can actually account for. R36a widened this from the
    # ledger alone to every input this artefact pins: §10 has to be able to name H2's
    # success counts and the stated-fix counts in order to correct a claim about them,
    # and a rule that forbids naming the number you are correcting is the wrong rule.
    scores = json.loads(SCORES.read_text(encoding='utf-8'))
    stated = Counter()
    for q in ledger['queries']:
        for s in SOURCES:
            stated[s] += len(q['by_source'][s]['branch_fix_stated_for_containing_range'])
    recomputable = {
        len(ledger['queries']): 'queries in the frozen ledger',
        len(ledger.get('skipped', [])): 'pairs excluded before the endpoint',
        len({q['package'] for q in ledger['queries']}): 'distinct packages',
    }
    for arm in ARMS:
        recomputable[scores['counts'][arm]['success']] = f'{arm} H2 successes'
    for s in SOURCES:
        recomputable[stated[s]] = f'{s} stated branch fixes'
    for raw in BARE_INTEGER.findall(body):
        value = int(raw.replace(',', ''))
        if value >= 100 and value not in recomputable:
            v.append(f'{raw} appears in the protocol but cannot be recomputed from the '
                     f'frozen ledger')
    if f'`{EXPECTED_PROTOCOL}`' not in body:
        v.append(f'the protocol does not name itself {EXPECTED_PROTOCOL}')
    return {'skipped_characters': skipped,
            'recomputable': {str(k): v2 for k, v2 in recomputable.items()},
            'violations': v, 'ok': not v}


# ---------------------------------------------------------------------------

def run(art, protocol=None, **_ignored):
    ledger = json.loads(QUERIES.read_text(encoding='utf-8'))
    scores = json.loads(SCORES.read_text(encoding='utf-8'))
    truth = recompute(ledger, scores)
    checks = {
        'protocol_declarations': check_protocol_declarations(ledger, protocol),
        'denominator_unchanged': check_denominator_unchanged(art, ledger),
        'oracle_coverage': check_oracle_coverage(ledger),
        'categories_recomputed': check_categories_recomputed(art, truth),
        'subclass_split': check_subclass_split(art, truth),
        'clearing_candidates': check_clearing_candidates(art, ledger),
        'declines_action_apart': check_declines_action_apart(art, truth),
        'union_baseline': check_union_baseline(art, truth),
        'paired_conversion': check_paired_conversion(art),
        'provenance_pinned': check_provenance_pinned(art),
        'package_level_labelled': check_package_level_labelled(art, ledger),
        'h2_linkage': check_h2_linkage(art, scores),
        'h2_untouched': check_h2_untouched(art),
        'concentration_disclosed': check_concentration_disclosed(art, ledger),
        'no_inference_emitted': check_no_inference_emitted(art),
    }
    return {'checks': checks, 'passed': all(c['ok'] for c in checks.values())}


# ------------------------------------------------------------------- mutations

def _f_category_flipped(d):
    for row in d['decisions']:
        if row['by_arm']['unified'].get('category') == 'post_remediation_exposure':
            row['by_arm']['unified']['category'] = 'decided'
            row['by_arm']['unified']['subclass'] = None
            return d
    return d


def _f_residual_emptied(d):
    for row in d['decisions']:
        if row['by_arm']['unified'].get('residual_ranges'):
            row['by_arm']['unified']['residual_ranges'] = []
            return d
    return d


def _f_subclass_relabelled(d):
    for row in d['decisions']:
        cell = row['by_arm']['unified']
        if cell.get('subclass') == 'cross_advisory_residual_exposure':
            cell['subclass'] = 'target_advisory_persists'
            return d
    return d


def _f_exposure_folded_into_decided(d):
    for arm in ARMS:
        moved = d['subclasses'][arm].pop('cross_advisory_residual_exposure', 0)
        d['counts'][arm]['decided'] += moved
        d['counts'][arm]['post_remediation_exposure'] -= moved
    return d


def _f_denominator_drift(d):
    d['denominator']['queries'] += 1
    return d


def _f_h2_hash_tampered(d):
    d['inputs_sha256']['h2_results.json'] = '0' * 64
    return d


def _f_concentration_removed(d):
    d.pop('concentration', None)
    return d


def _f_p_value_inserted(d):
    d['counts']['unified']['p_value'] = 0.001
    return d


def _f_residual_count_desynced(d):
    for row in d['decisions']:
        cell = row['by_arm']['unified']
        if cell.get('residual_range_count'):
            cell['residual_range_count'] = 1
            return d
    return d


def _f_residue_claimed_on_undecidable(d):
    for row in d['decisions']:
        cell = row['by_arm']['nvd']
        if cell.get('category') == 'undecidable':
            # A zero here reads as "nothing still hits you" on a row that never
            # installed anything.
            cell['residual_range_count'] = 0
            cell['residual_ranges'] = []
            return d
    return d


def _f_unparseable_clearing_candidate(d):
    for row in d['decisions']:
        cell = row['by_arm']['unified']
        if cell.get('category') == 'post_remediation_exposure':
            # Leading zero: npm rejects it, so it satisfies nothing and looks clean.
            cell['candidates_that_would_clear'] = ['2026.03.28']
            return d
    return d


def _f_declines_folded_back(d):
    for row in d['decisions']:
        for arm in ARMS:
            cell = row['by_arm'][arm]
            if cell.get('disposition') == 'declines_action':
                cell['category'] = 'undecidable'
                cell['subclass'] = 'declines_action'
                d['counts'][arm]['undecidable'] += 1
                d['declines_action']['counts'][arm] -= 1
                return d
    return d


def _f_union_baseline_copied_from_primary(d):
    for arm in ARMS:
        d['secondary_union_baseline']['counts'][arm] = dict(d['counts'][arm])
    return d


def _f_paired_table_on_wrong_base(d):
    d['paired_conversion']['unified|osv']['counts']['decided']['unified'] = 939
    return d


def _f_union_subclass_bent(d):
    subs_ = d['secondary_union_baseline']['subclasses']['osv']
    if 'cross_advisory_residual_exposure' in subs_:
        subs_['cross_advisory_residual_exposure'] += 3
    return d


def _f_transitions_bent(d):
    blk = d['paired_conversion']['unified|ghsa']['transitions']
    for k in list(blk):
        blk[k] += 1
        break
    return d


def _f_provenance_stale(d):
    d['provenance_sha256']['generator'] = '0' * 64
    return d


def _f_git_commit_smuggled(d):
    d['provenance_sha256']['git_commit'] = 'deadbeef'
    return d


def _f_package_label_reverted(d):
    for arm in ARMS:
        cell = d['per_package']['counts'][arm]
        cell['packages_with_any_query'] = cell.pop(
            'packages_with_evaluable_post_remediation_category')
    return d


def _f_index_entry_removed(d):
    for row in d['decisions']:
        for rng in row['by_arm']['unified'].get('residual_ranges') or []:
            key = f'unified|{row["package"]}|{rng}'
            if key in d['residual_range_index']:
                del d['residual_range_index'][key]
                return d
    return d


FAULTS = [
    ('a category flipped to decided', _f_category_flipped),
    ('the residue behind an exposure emptied', _f_residual_emptied),
    ('a cross-advisory residue relabelled as the target advisory',
     _f_subclass_relabelled),
    ('cross-advisory exposure folded into decided', _f_exposure_folded_into_decided),
    ('the denominator drifting by one', _f_denominator_drift),
    ('the sealed H2 hash tampered with', _f_h2_hash_tampered),
    ('the concentration disclosure removed', _f_concentration_removed),
    ('a p-value smuggled into the counts', _f_p_value_inserted),
    ('a residual count that no longer matches its own list',
     _f_residual_count_desynced),
    ('a clean-looking zero residue on a row that installed nothing',
     _f_residue_claimed_on_undecidable),
    ('a residual range with no provenance entry behind it', _f_index_entry_removed),
    ('declines_action folded back into undecidable', _f_declines_folded_back),
    ('the union baseline copied from the primary one',
     _f_union_baseline_copied_from_primary),
    ('a paired figure taken from the wrong denominator', _f_paired_table_on_wrong_base),
    ('a union subclass count bent away from its rows', _f_union_subclass_bent),
    ('a transition cell bent away from the margins', _f_transitions_bent),
    ('provenance pointing at a generator that is not on disk', _f_provenance_stale),
    ('a git commit smuggled into the provenance block', _f_git_commit_smuggled),
    ('the package-level field renamed back to what it does not count',
     _f_package_label_reverted),
    ('an unparseable string offered as the version that clears the package',
     _f_unparseable_clearing_candidate),
]


def _f_protocol_number_unaccounted(state):
    """A count in the protocol that the frozen ledger cannot account for."""
    state['protocol'] = state['protocol'].replace(
        '账本的 **2,927** 条查询',
        '账本的 **2,927** 条查询(其中 **1,742** 条来自主要来源)', 1)
    return state


def self_test():
    data = ARTEFACT.read_bytes()
    doc = PROTOCOL_DOC.read_text(encoding='utf-8')

    def fresh():
        return {'art': json.loads(data.decode('utf-8')), 'protocol': doc}

    def on_artefact(fault):
        def wrapped(state):
            state['art'] = fault(state['art'])
            return state
        return wrapped

    base = run(**fresh())
    print(f"  [{'PASS' if base['passed'] else 'FAIL'}] baseline: the artefact follows "
          f"from the frozen ledger")
    if not base['passed']:
        for name, c in base['checks'].items():
            if not c['ok']:
                print(f'    {name}: {c["violations"][:3]}')
        print('TEST SETUP FAILURE')
        return 1

    faults = [(label, on_artefact(f)) for label, f in FAULTS] + [
        ('a protocol count nothing can recompute', _f_protocol_number_unaccounted),
    ]
    caught = 0
    for label, fault in faults:
        got = run(**fault(fresh()))
        if got['passed']:
            print(f'  [NOT CAUGHT] {label}')
            continue
        caught += 1
        by = ', '.join(n for n, c in got['checks'].items() if not c['ok'])
        print(f'  [PASS] {label}: caught by {by}')
    ok = caught == len(faults)
    print(f"SELF-TEST: {'PASS' if ok else 'FAIL'}: {caught}/{len(faults)} caught")
    return 0 if ok else 1


def main():
    if '--self-test' in sys.argv:
        return self_test()
    if not ARTEFACT.exists():
        print(f'{ARTEFACT.name} is missing - run derive_h2_cicd.py first')
        return 1
    report = run(json.loads(ARTEFACT.read_text(encoding='utf-8')))
    if '--json' in sys.argv:
        print(json.dumps(report, ensure_ascii=False, indent=1, sort_keys=True))
    else:
        for name, c in report['checks'].items():
            print(f"  [{'PASS' if c['ok'] else 'FAIL'}] {name}")
            for line in c['violations'][:6]:
                print(f'         {line}')
    print(f"H2 CI/CD: {'PASS' if report['passed'] else 'FAIL'}")
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
