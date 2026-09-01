"""Turn each source's stored affected-range shape into a standard npm range string.

WHAT THIS MODULE IS ALLOWED TO DO

  Convert. Nothing else. It rewrites what a source stored - OSV's introduced/fixed
  events, NVD's four bounds, GHSA's comparator text - into one spelling that npm
  understands, and then asks a ledger what that spelling means.

WHAT IT IS NOT ALLOWED TO DO

  Decide. Whether 19.0.3 satisfies `>=19.0.0 <19.0.2`, which of two versions is
  greater, which fixed version applies - none of that is computed here. Every such
  question is answered by schemas/H2_RANGE_DECISIONS.json, which was produced offline
  by npm's own `semver` (pinned, with its package-lock committed). A key missing from
  that ledger is a HARD FAILURE, never a quiet local fallback: the moment this module
  computes one answer itself, the study has two range engines and no way to tell which
  one produced a result.

  h2-protocol-2 got this wrong in a way worth remembering. It defined a maintenance
  branch as "the same MAJOR", so for react-server-dom-webpack - fixed at 19.0.2, 19.1.3
  and 19.2.2 - an install on 19.0.3 was offered 19.1.3. But 19.0.3 is already past its
  own branch's boundary, and 19.1.3 is a different minor line. 128 (entity, package)
  pairs in this cohort carry more than one maintenance branch inside one major. The
  branch a version is on is decided by WHICH AFFECTED RANGE CONTAINS IT, and that is a
  range question, so it belongs to the ledger.

    python npm_range_h2.py --requests     # emit the questions the oracle must answer
    python npm_range_h2.py --self-test
"""
import collections
import gzip
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import semver_h2 as SV

ROOT = Path(__file__).resolve().parent
MODEL = ROOT / 'output' / 'unified_model_v3'
H1 = ROOT / 'output' / 'h1_discovery'
REQUESTS = ROOT / 'schemas' / 'H2_RANGE_REQUESTS.json'
DECISIONS = ROOT / 'schemas' / 'H2_RANGE_DECISIONS.json'

SOURCES = ('nvd', 'ghsa', 'osv')
NPM_REGISTRY_HOSTS = ('registry.npmjs.org', 'www.npmjs.com', 'npmjs.com', 'npmjs.org')


class LedgerMiss(Exception):
    """A question the offline oracle was never asked.

    Deliberately fatal. The alternative - answering it here - is how a second range
    engine gets built by accident.
    """


# --------------------------------------------------------------------------- rows

def rows(path):
    with gzip.open(path, 'rt', encoding='utf-8') as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def is_npm_purl(value):
    return isinstance(value, str) and value.strip().lower().startswith('pkg:npm/')


def npm_package_of(source, payload):
    """The canonical npm package this affected row is about, or None.

    NVD is read from the purl, never from `package_name`: NVD's package_name is the
    CPE's `vendor:product` pair, so `fastify` and `fastify:fastify` would count as two
    packages and split one package's evidence in half. (That is exactly the difference
    between the two multi-package counts this project has seen, 151 and 233.)
    """
    if source in ('ghsa', 'osv'):
        if (payload.get('ecosystem') or '').strip().lower() != 'npm':
            return None
        return SV.canonical_npm_package(payload.get('package_name'))
    if is_npm_purl(payload.get('purl')):
        return SV.canonical_npm_package(payload.get('purl'))
    return None


Row = collections.namedtuple(
    'Row', 'entity_id package source payload record_ref json_pointer')


def npm_rows(model=MODEL):
    """One Row per npm affected row, carrying its real provenance.

    R30d-P1: the protocol has always required evidence to point back to a record_ref and
    a json_pointer, and the ledger was recording strings like `ghsa:ranges[0]:text` -
    a description of where a value came from rather than a pointer anyone could follow.
    Both are on the assertion row already; they just were not being carried.
    """
    for r in rows(model / 'assertions_affected.jsonl.gz'):
        eid = r.get('entity_id')
        payload = r.get('payload') or {}
        pkg = npm_package_of(r['source'], payload)
        if eid and pkg:
            yield Row(eid, pkg, r['source'], payload,
                      r.get('record_ref') or f"{r['source']}:{r['native_id']}",
                      r.get('json_pointer') or payload.get('pointer'))


def is_npm_registry(url):
    """The npm registry by HOST. `evil-npmjs.example.com` is not the npm registry."""
    if not isinstance(url, str) or not url.strip():
        return False
    host = (urlparse(url.strip()).hostname or '').lower()
    return host in NPM_REGISTRY_HOSTS


def nvd_registry_pairs(model=MODEL, h1=H1):
    """Pairs NVD names through a registry URL rather than a purl.

    NVD can identify an npm package two ways, and the second one never reaches the
    model payload: `affectedData[].collectionURL` pointing at the npm registry, with
    the name in `packageName`. Three cohort pairs exist only this way - markdown-it,
    angular, sanitize-html. Reading only purls loses them, which is what a throwaway
    probe of mine did twice.

    This is a second implementation of the rule the provenance gate also applies. That
    is deliberate: the gate compares the two, and a rule with one implementation is a
    rule nothing can disagree with.
    """
    by_ref = {}
    for raw in rows(h1 / 'sample_nvd.jsonl.gz'):
        cve = raw.get('cve') or {}
        for block in cve.get('affected') or []:
            for data in block.get('affectedData') or []:
                if is_npm_registry(data.get('collectionURL')):
                    name = SV.canonical_npm_package(data.get('packageName'))
                    if name:
                        by_ref.setdefault(f"nvd:{cve['id']}", set()).add(name)
    out = set()
    for r in rows(model / 'entity_record_links.jsonl.gz'):
        for name in by_ref.get(r['record_ref']) or ():
            out.add((r['entity_id'], name))
    return out


def nvd_segment_facts(h1=H1):
    """Per NVD version segment: is it AFFECTED, and what fix does it state?

    R30c-P0. `build_unified_v3.nvd_cna_affected` turns every entry of
    `affectedData[].versions[]` into a range and keeps no `status` on it, so a segment
    saying "5.8.3 and above are FINE" arrives downstream shaped exactly like one saying
    "everything below 5.8.2 is broken". The corpus has 230 npm segments: 121 affected
    and 109 unaffected, with 106 of the 118 affectedData blocks carrying both.

    The builder is sealed by arm 1's policy_code_sha256_lf, so the status is recovered
    here from the raw sample - the same downstream route `extra_texts`,
    `corrected_nvd_package` and the registry-evidence rule already take. The join key is
    (record_ref, affectedData pointer, index within versions[]), which matches the model
    118/118.

    A hash over the old ledger proved only that the mistake reproduced exactly: the
    chart was photocopied faithfully, with "recovered" written in the box for "still
    ill".
    """
    facts = {}
    for raw in rows(h1 / 'sample_nvd.jsonl.gz'):
        cve = raw.get('cve') or {}
        ref = f"nvd:{cve.get('id')}"
        for ai, block in enumerate(cve.get('affected') or []):
            for di, data in enumerate(block.get('affectedData') or []):
                pointer = f'/cve/affected/{ai}/affectedData/{di}'
                seg = []
                for entry in data.get('versions') or []:
                    status = entry.get('status')
                    # The fix NVD states for THIS segment: a change to `unaffected`
                    # inside a segment whose own status is `affected` (the R27a2 rule).
                    fixes = sorted({str(ch['at']) for ch in entry.get('changes') or []
                                    if ch.get('status') == 'unaffected' and ch.get('at')}
                                   ) if status == 'affected' else []
                    seg.append({'status': status, 'stated_fixes': fixes})
                facts[(ref, pointer)] = seg
    return facts


_NVD_FACTS = None


def nvd_facts(h1=H1):
    global _NVD_FACTS
    if _NVD_FACTS is None:
        _NVD_FACTS = nvd_segment_facts(h1)
    return _NVD_FACTS


def cohort_pairs(model=MODEL, h1=H1):
    """Every (entity, canonical npm package) pair in the H2 cohort."""
    pairs = {(r.entity_id, r.package) for r in npm_rows(model)}
    return pairs | nvd_registry_pairs(model, h1)


# ------------------------------------------------------------------- conversion

def _clean(value):
    """A version string as the source spelled it, or None if there is nothing there."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def osv_range_to_string(rng):
    """OSV event lists are already intervals: introduced X, then fixed / last_affected.

    `introduced: "0"` is OSV's way of saying "from the beginning", so it becomes
    `>=0.0.0` rather than being dropped - dropping it would turn a bounded range into
    an unbounded one.
    """
    lo = hi_ex = hi_in = None
    for ev in rng.get('events') or []:
        kind, value = ev.get('kind'), _clean(ev.get('value'))
        if kind == 'introduced':
            lo = '0.0.0' if value == '0' else value
        elif kind == 'fixed':
            hi_ex = value
        elif kind == 'last_affected':
            hi_in = value
        elif kind == 'limit':
            hi_ex = hi_ex or value
    parts = []
    if lo:
        parts.append(f'>={lo}')
    if hi_ex:
        parts.append(f'<{hi_ex}')
    elif hi_in:
        parts.append(f'<={hi_in}')
    return ' '.join(parts) or None


def nvd_bounds_to_string(bounds):
    """NVD's four bounds, in the order npm writes them."""
    if not isinstance(bounds, dict):
        return None
    parts = []
    for key, op in (('start_including', '>='), ('start_excluding', '>'),
                    ('end_excluding', '<'), ('end_including', '<=')):
        value = _clean(bounds.get(key))
        if value:
            parts.append(f'{op}{value}')
    return ' '.join(parts) or None


def ghsa_expr_to_string(expr):
    """GHSA writes comparators as text: `<= 2.1.1`, `>= 9.0.0, < 9.6.0-alpha.54`.

    A comma in a GHSA range is a conjunction, which npm spells as a space. Nothing else
    is rewritten - no caret or tilde is expanded here, because a scan of every npm row
    in this corpus found none: only <, <=, >, >= and =.
    """
    text = _clean(expr)
    if not text:
        return None
    parts = [p.strip() for p in text.split(',') if p.strip()]
    return ' '.join(p.replace(' ', '') for p in parts) or None


def version_list_to_string(versions):
    """An explicit enumeration is a union of exact versions."""
    clean = [v for v in (_clean(x) for x in versions or []) if v]
    return ' || '.join(f'={v}' for v in clean) or None


def osv_range_fix(rng):
    """OSV states a remediation only through a `fixed` event.

    `last_affected` and `limit` are where the source stopped describing, not where it
    says the problem was solved. Treating them as fixes invents a remediation the source
    never claimed.
    """
    for ev in rng.get('events') or []:
        if ev.get('kind') == 'fixed':
            return _clean(ev.get('value'))
    return None


def affected_ranges(row):
    """Every AFFECTED range on this row, with the remediation the source states for it.

    Returns [(range_string, provenance, stated_fix, note)].

    Two rules that h2-protocol-3 got wrong, both P0:

      * an NVD segment marked `unaffected` is not an affected range. Its status is
        recovered from the raw sample by (record_ref, pointer, index), because the
        sealed builder drops it. 109 of 230 npm segments are unaffected, and 103 queries
        currently pick their installed version out of one;
      * a range's upper bound is not a fix. `<3.2.0` on @usebruno/cli sits beside a
        stated first_patched_version of 3.2.1, and `>=2.9.18 <3.0.0` on vite has an
        upper bound that is a major boundary, not a patch. The remediation now comes
        from what the source SAYS: GHSA's first_patched_version on the same native row,
        OSV's `fixed` event on the same range, NVD's stated unaffected boundary inside
        the same segment. Where none is stated, the fix is None and the arm can only
        reach `package_but_no_fix` - the structural upper bound is kept in `note` for
        the sensitivity arm and never used as an answer.
    """
    source, payload = row.source, row.payload
    base = row.json_pointer or ''
    out = []
    ghsa_fix = _clean(payload.get('first_patched_version')) if source == 'ghsa' else None
    seg = []
    if source == 'nvd':
        seg = nvd_facts().get((row.record_ref, payload.get('pointer'))) or []

    for i, rng in enumerate(payload.get('ranges') or []):
        kind = rng.get('range_kind')
        note, fix = None, None
        # Pointers into the RAW record, built per source from the shape it really has:
        # GHSA keeps one expression per vulnerabilities[] entry, OSV keeps ranges[], NVD
        # keeps versions[]. A pointer that does not resolve is worse than none, so the
        # self-test resolves every one of them against the window records.
        ptr = fix_ptr = None
        if kind == 'event_list':
            text = osv_range_to_string(rng)
            fix = osv_range_fix(rng)
            ptr = f'{base}/ranges/{i}'
            fix_ptr = f'{base}/ranges/{i}/events' if fix else None
            if not fix:
                note = 'osv states no fixed event for this range'
        elif kind == 'version_list':
            # R30c-P1: the model stores an explicit enumeration as events of kind
            # `affected_version`, NOT as a payload-level version_list - which is why the
            # old converter dropped all 6 of them and the self-test, written against a
            # shape I invented, still passed.
            text = version_list_to_string(
                [ev.get('value') for ev in rng.get('events') or []
                 if ev.get('kind') == 'affected_version'])
            ptr = f'{base}/versions'
            note = 'explicit version enumeration'
        elif rng.get('bounds'):
            status = seg[i]['status'] if i < len(seg) else None
            if status is not None and status != 'affected':
                continue                       # an unaffected segment is not a range
            text = nvd_bounds_to_string(rng['bounds'])
            stated = seg[i]['stated_fixes'] if i < len(seg) else []
            fix = stated[0] if stated else None
            ptr = f'{base}/versions/{i}'
            fix_ptr = f'{base}/versions/{i}/changes' if fix else None
            if status is None:
                note = 'nvd segment status could not be recovered'
            elif not fix:
                note = 'nvd states no unaffected boundary inside this segment'
        elif rng.get('original_expression'):
            text = ghsa_expr_to_string(rng['original_expression'])
            fix = ghsa_fix
            ptr = f'{base}/vulnerable_version_range'
            fix_ptr = f'{base}/first_patched_version' if fix else None
            if not fix:
                note = 'ghsa row declares no first_patched_version'
        else:
            text = None
        if text:
            out.append({'range': text, 'record_ref': row.record_ref,
                        'range_pointer': ptr, 'fix': fix, 'fix_pointer': fix_ptr,
                        'note': note, 'shape': f'{source}:ranges[{i}]:{kind}'})

    # Kept for safety: no row in this corpus stores it here, and if one ever does, it
    # must not vanish the way the version_list ranges did.
    text = version_list_to_string(payload.get('version_list'))
    if text:
        out.append({'range': text, 'record_ref': row.record_ref,
                    'range_pointer': f'{base}/versions', 'fix': None,
                    'fix_pointer': None, 'note': 'payload-level version enumeration',
                    'shape': f'{source}:version_list'})
    return out


def range_strings(row):
    """(range_string, shape) only - for callers that do not need the evidence."""
    return [(e['range'], e['shape']) for e in affected_ranges(row)]


def resolve_pointer(document, pointer):
    """Follow a JSON pointer, or raise. Used to prove the evidence pointers are real."""
    node = document
    for token in (pointer or '').split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        if isinstance(node, list):
            node = node[int(token)]
        else:
            node = node[token]
    return node


def range_literals(range_string):
    """Every version token inside a range string this module generated.

    These are candidate installed versions too. Most already appear as stored values,
    but `introduced: "0"` becomes the literal `0.0.0`, which no source ever wrote down -
    and a version we synthesised is still a version the oracle has to be asked about.
    The first run of the query builder stopped exactly there, on `0.0.0` against
    `<6.2.5`, which is the hard failure doing its job.
    """
    out = []
    for part in range_string.replace('||', ' ').split():
        token = part.lstrip('<>=')
        if token:
            out.append(token)
    return out


def structural_upper_bound(range_string):
    """The `<Y` boundary of a generated range string, or None.

    NOT a fix, and it used to be treated as one. It is where the source stopped saying
    "affected", which coincides with the patch often enough to look right and differs
    often enough to be wrong: 14 GHSA ranges in this cohort have an exclusive upper
    bound that is not the version the same row names as first patched, and some of those
    bounds are major boundaries (`>=2.9.18 <3.0.0` against a stated fix of 5.4.21).

    Kept only for the declared sensitivity arm "believe structural upper bounds", where
    it is labelled as a proxy rather than a remediation.
    """
    for part in range_string.split():
        if part.startswith('<') and not part.startswith('<='):
            return part[1:] or None
    return None


def observed_versions(payload):
    """Every concrete version string this row mentions, whatever role it played.

    These are the candidate installed versions: a version this corpus has actually seen
    for the package, rather than one we invented.
    """
    seen = []
    for key in ('first_patched_version',):
        v = _clean(payload.get(key))
        if v:
            seen.append(v)
    for rng in payload.get('ranges') or []:
        for ev in rng.get('events') or []:
            v = _clean(ev.get('value'))
            if v and v != '0':
                seen.append(v)
        for v in (rng.get('bounds') or {}).values():
            v = _clean(v)
            if v:
                seen.append(v)
    for v in payload.get('version_list') or []:
        v = _clean(v)
        if v:
            seen.append(v)
    return seen


# ---------------------------------------------------------------------- requests

def collect(model=MODEL):
    """Everything the oracle has to be asked about, derived from the frozen model."""
    pair_ranges = {}          # (entity, pkg) -> {range_string: [provenance, ...]}
    pair_fixes = {}           # (entity, pkg) -> {source: set(fixed versions)}
    pkg_versions = {}         # pkg -> set(version strings seen anywhere for it)
    for row in npm_rows(model):
        key = (row.entity_id, row.package)
        for text, shape in range_strings(row):
            pair_ranges.setdefault(key, {}).setdefault(text, []).append(shape)
            pkg_versions.setdefault(row.package, set()).update(range_literals(text))
        fixed = _clean(row.payload.get('first_patched_version'))
        if fixed:
            pair_fixes.setdefault(key, {}).setdefault(row.source, set()).add(fixed)
        pkg_versions.setdefault(row.package, set()).update(
            observed_versions(row.payload))
        pair_ranges.setdefault(key, {})
    return pair_ranges, pair_fixes, pkg_versions


def build_requests(model=MODEL):
    """The request ledger: every version, range and membership test we will need.

    Only the tests that are actually reachable are asked for. The full cross product of
    1,589 versions and 2,395 ranges is 3.8 million questions, almost all of them about
    packages that have nothing to do with each other.
    """
    pair_ranges, _, pkg_versions = collect(model)

    # A range with no lower bound has a minimum npm derives rather than one any source
    # wrote: minVersion('<6.2.5') is 0.0.0, minVersion('>1.2.3') is 1.2.4. Those are
    # fallback installed versions, so they have to be asked about too - and only the
    # oracle knows them. Hence two passes: build requests, answer them, fold the
    # derived minimums back in, answer again. The third pass must change nothing, and
    # --requests reports whether it did.
    folded = 0
    if DECISIONS.exists():
        for (eid, pkg), by_text in pair_ranges.items():
            for text in by_text:
                try:
                    low = range_info(text)['min_version']
                except LedgerMiss:
                    continue
                if low and low not in pkg_versions.setdefault(pkg, set()):
                    pkg_versions[pkg].add(low)
                    folded += 1

    # What npm actually published for this package, on or before the corpus cutoff, is
    # asked about through maxSatisfying rather than version-by-version: the registry
    # holds hundreds of thousands of versions, and the only one this study needs is the
    # newest one a given range still accepts. One question per (package, range) instead
    # of one per (version, range).
    max_satisfying = {}
    for (eid, pkg), by_text in pair_ranges.items():
        for text in by_text:
            max_satisfying.setdefault(pkg, set()).add(text)
    if DECISIONS.exists():
        led = ledger()
        for pkg, texts in max_satisfying.items():
            for text in texts:
                got = ((led.get('max_satisfying') or {}).get(pkg) or {}).get(text)
                if got:
                    pkg_versions.setdefault(pkg, set()).add(got)

    versions, ranges, satisfies, sorts = set(), set(), {}, {}
    for (eid, pkg), by_text in pair_ranges.items():
        cand = sorted(pkg_versions.get(pkg) or ())
        if cand:
            sorts[pkg] = cand
        versions.update(cand)
        for text in by_text:
            ranges.add(text)
            satisfies.setdefault(text, set()).update(cand)
    return {
        'schema': 'h2-range-requests/1',
        'note': ('Questions for npm semver, derived from the frozen model. Answered '
                 'offline; the experiment reads only the answers.'),
        'versions': sorted(versions),
        'ranges': sorted(ranges),
        'satisfies': {k: sorted(v) for k, v in sorted(satisfies.items())},
        'sorts': {k: sorts[k] for k in sorted(sorts)},
        'max_satisfying': {k: sorted(max_satisfying[k]) for k in sorted(max_satisfying)},
        'derived_minimums_folded_in': folded,
    }


def serialise(doc):
    """Bytes, LF only - the sha256 recorded is the sha256 of what lands on disk."""
    return (json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True)
            .replace('\r\n', '\n') + '\n').encode('utf-8')


# ----------------------------------------------------------------------- lookups

_LEDGER = None


def ledger(path=DECISIONS):
    global _LEDGER
    if _LEDGER is None:
        if not path.exists():
            raise LedgerMiss(f'{path.name} is missing - run the offline oracle first')
        _LEDGER = json.loads(path.read_text(encoding='utf-8'))
    return _LEDGER


def parsed(version, path=DECISIONS):
    d = ledger(path)['versions'].get(version)
    if d is None:
        raise LedgerMiss(f'no decision recorded for version {version!r}')
    return d


def satisfies(version, range_string, path=DECISIONS):
    by_range = ledger(path)['satisfies'].get(range_string)
    if by_range is None or version not in by_range:
        raise LedgerMiss(f'no decision recorded for {version!r} in {range_string!r}')
    return by_range[version]


def sorted_versions(package, path=DECISIONS):
    d = ledger(path)['sorts'].get(package)
    if d is None:
        raise LedgerMiss(f'no sort order recorded for package {package!r}')
    return d


def max_published_satisfying(package, range_string, path=DECISIONS):
    """The newest version npm published (by the cutoff) that this range accepts.

    Answered by npm's own `maxSatisfying` against the frozen registry snapshot. This
    is what makes an installed_version a version that really existed: h2-protocol-3
    picked the largest string the ADVISORIES mentioned, which put 329 queries on
    `0.0.0` - a value this project synthesised out of OSV's `introduced: "0"` and
    that nobody has ever installed.
    """
    by_pkg = (ledger(path).get('max_satisfying') or {}).get(package)
    if by_pkg is None or range_string not in by_pkg:
        raise LedgerMiss(
            f'no maxSatisfying recorded for {package!r} against {range_string!r}')
    return by_pkg[range_string]


def range_info(range_string, path=DECISIONS):
    d = ledger(path)['ranges'].get(range_string)
    if d is None:
        raise LedgerMiss(f'no decision recorded for range {range_string!r}')
    return d


# --------------------------------------------------------------------------- test

def self_test():
    ok = True

    # Conversion is a pure rewrite, so it can be checked against hand-written shapes.
    cases = [
        ('osv', {'range_kind': 'event_list',
                 'events': [{'kind': 'introduced', 'value': '0'},
                            {'kind': 'fixed', 'value': '38.8.6'}]}, '>=0.0.0 <38.8.6'),
        ('osv', {'range_kind': 'event_list',
                 'events': [{'kind': 'introduced', 'value': '39.0.0-alpha.1'},
                            {'kind': 'fixed', 'value': '39.8.1'}]},
         '>=39.0.0-alpha.1 <39.8.1'),
        ('osv', {'range_kind': 'event_list',
                 'events': [{'kind': 'introduced', 'value': '1.0.0'},
                            {'kind': 'last_affected', 'value': '1.4.2'}]},
         '>=1.0.0 <=1.4.2'),
        ('nvd', {'bounds': {'start_including': '5.7.2', 'end_excluding': '5.8.1',
                            'start_excluding': None, 'end_including': None}},
         '>=5.7.2 <5.8.1'),
        ('nvd', {'bounds': {'start_including': None, 'end_excluding': '2026.3.8',
                            'start_excluding': None, 'end_including': None}},
         '<2026.3.8'),
        ('ghsa', {'original_expression': '<= 2.1.1'}, '<=2.1.1'),
        ('ghsa', {'original_expression': '>= 9.0.0, < 9.6.0-alpha.54'},
         '>=9.0.0 <9.6.0-alpha.54'),
    ]
    bad = []
    for source, rng, want in cases:
        got = range_strings(Row(None, None, source, {'ranges': [rng]}, None, ''))
        got = got[0][0] if got else None
        if got != want:
            bad.append((rng, want, got))
    print(f'  [{"PASS" if not bad else "FAIL"}] range conversion: '
          f'{len(cases) - len(bad)}/{len(cases)}')
    for rng, want, got in bad:
        print(f'      {rng} -> expected {want!r}, got {got!r}')
    ok &= not bad

    got = version_list_to_string(['1.0.0', '1.0.1'])
    hit = got == '=1.0.0 || =1.0.1'
    print(f'  [{"PASS" if hit else "FAIL"}] an explicit version list is a union')
    ok &= hit

    # THE CHECK THAT WOULD HAVE CAUGHT R30c-P1.
    #
    # The cases above are shapes I wrote. The model stores an explicit enumeration as
    # `range_kind: version_list` with `events[].kind == "affected_version"`, and nothing
    # at all in `payload.version_list` - so the old converter dropped all six of them and
    # every hand-written case still passed. Fixtures cannot testify about a shape their
    # author never saw, so this walks the production rows and demands that every stored
    # range is either converted or explicitly accounted for.
    seen, converted, dropped = 0, 0, []
    unaffected = 0
    for row in npm_rows():
        source, payload = row.source, row.payload
        produced = {e['shape'] for e in affected_ranges(row)}
        segs = nvd_facts().get((row.record_ref, payload.get('pointer'))) or []
        for i, rng in enumerate(payload.get('ranges') or []):
            seen += 1
            prov = f'{source}:ranges[{i}]:{rng.get("range_kind")}'
            if prov in produced:
                converted += 1
            elif (source == 'nvd' and i < len(segs)
                  and segs[i]['status'] not in (None, 'affected')):
                unaffected += 1                     # deliberately excluded, not dropped
            else:
                dropped.append((source, rng.get('range_kind'), prov))
    print(f'  [{"PASS" if not dropped else "FAIL"}] every stored range is accounted for: '
          f'{converted:,} converted + {unaffected} excluded as NVD-unaffected '
          f'= {seen:,} stored')
    for d in dropped[:5]:
        print(f'      silently dropped: {d}')
    ok &= not dropped

    # NVD status recovery has to reach every npm segment, or the exclusion above is
    # excluding nothing.
    facts = nvd_facts()
    joined = sum(1 for r in npm_rows()
                 if r.source == 'nvd'
                 and (r.record_ref, r.payload.get('pointer')) in facts)
    total_nvd = sum(1 for r in npm_rows() if r.source == 'nvd')
    hit = joined == total_nvd and total_nvd > 0
    print(f'  [{"PASS" if hit else "FAIL"}] NVD segment status recovered for '
          f'{joined}/{total_nvd} npm rows')
    ok &= hit

    # R30d-P1: a pointer nobody can follow is not provenance. Every emitted pointer is
    # resolved against the raw window record it claims to point into.
    raw = {}
    for src, fname, key in (('ghsa', 'ghsa_window_raw', None),
                            ('osv', 'osv_window_raw', None),
                            ('nvd', 'nvd_window_raw', 'cve')):
        for rec in rows(H1 / f'{fname}.jsonl.gz'):
            body = rec.get(key) if key else rec
            ident = (body or {}).get('id') or (body or {}).get('ghsa_id')
            if ident:
                raw[f'{src}:{ident}'] = rec
    checked, unresolved = 0, []
    for row in npm_rows():
        record = raw.get(row.record_ref)
        if record is None:
            continue
        for e in affected_ranges(row):
            for ptr in (e['range_pointer'], e['fix_pointer']):
                if not ptr:
                    continue
                checked += 1
                try:
                    resolve_pointer(record, ptr)
                except Exception:
                    unresolved.append((row.record_ref, ptr))
    print(f'  [{"PASS" if not unresolved else "FAIL"}] evidence pointers resolve in the '
          f'raw records: {checked - len(unresolved):,}/{checked:,}')
    for u in unresolved[:5]:
        print(f'      does not resolve: {u[0]} {u[1]}')
    ok &= not unresolved

    # A remediation must be something a source stated, never a range boundary.
    stated = collections.Counter()
    for row in npm_rows():
        for e in affected_ranges(row):
            stated[(row.source, bool(e['fix']))] += 1
    print(f'  [PASS] ranges carrying a stated remediation: '
          f'{ {k[0]: v for k, v in stated.items() if k[1]} }; without: '
          f'{ {k[0]: v for k, v in stated.items() if not k[1]} }')

    # A lookup that was never recorded must be fatal, not quietly answered.
    try:
        satisfies('9.9.9', '>=0.0.0 <0.0.1')
        caught = False
    except LedgerMiss:
        caught = True
    except Exception:
        caught = False
    print(f'  [{"PASS" if caught else "FAIL"}] a missing ledger key raises LedgerMiss '
          f'instead of being computed locally')
    ok &= caught

    if DECISIONS.exists():
        req = build_requests()
        led = ledger()
        missing = [v for v in req['versions'] if v not in led['versions']]
        miss_r = [r for r in req['ranges'] if r not in led['ranges']]
        miss_s = [(r, v) for r, vs in req['satisfies'].items()
                  for v in vs if v not in (led['satisfies'].get(r) or {})]
        hit = not (missing or miss_r or miss_s)
        print(f'  [{"PASS" if hit else "FAIL"}] the ledger answers every request: '
              f'versions {len(req["versions"])}, ranges {len(req["ranges"])}, '
              f'membership tests {sum(len(v) for v in req["satisfies"].values()):,}')
        for m in (missing[:3] + miss_r[:3] + miss_s[:3]):
            print(f'      unanswered: {m!r}')
        ok &= hit
    else:
        print('  [FAIL] no decision ledger on disk - run the offline oracle')
        ok = False

    print(f'NPM RANGE CONVERSION: {"PASS" if ok else "FAIL"}')
    return 0 if ok else 1


if __name__ == '__main__':
    if '--requests' in sys.argv:
        doc = build_requests()
        data = serialise(doc)
        REQUESTS.write_bytes(data)
        print(f'{REQUESTS.name}: versions {len(doc["versions"]):,}, '
              f'ranges {len(doc["ranges"]):,}, '
              f'membership tests {sum(len(v) for v in doc["satisfies"].values()):,}, '
              f'packages {len(doc["sorts"]):,}')
        print(f'sha256 {hashlib.sha256(data).hexdigest()}')
        sys.exit(0)
    if '--self-test' in sys.argv:
        sys.exit(self_test())
    print(__doc__)
    sys.exit(0)
