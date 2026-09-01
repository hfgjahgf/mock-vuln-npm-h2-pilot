"""Parsing, ordering and package-name canonicalisation. No branch selection.

WHAT WAS REMOVED IN R30b, AND WHY IT MATTERS

  This module used to answer "which fixed version applies to this install", with a
  maintenance branch defined as the same MAJOR. That definition is wrong, and measurably
  so. Against the frozen query ledger, on the 1,784 (query, source) cases where a source
  both places the install inside an affected range and names a fixed version:

      1,446  the MAJOR rule agrees with the range the install is actually inside
        335  the MAJOR rule DISCARDS a real fix - `>=0.0.0 <1.3.2` on node-forge means
             "upgrade to 1.3.2", but 0.0.0 and 1.3.2 are different majors, so the rule
             returned "no applicable branch" and the arm would have been scored as
             having failed to answer
          3  the MAJOR rule picks the wrong version - @angular/ssr installed at
             21.2.0-next.0 should be offered 21.2.0-rc.0, and the rule offered
             21.2.0-rc.1

  The 335 is the serious one. It is not a mis-selection, it is correct advice being
  thrown away, and it falls hardest on whichever arm contributes the most rows - which
  is exactly the comparison H2 rests on. A branch is decided by WHICH AFFECTED RANGE
  CONTAINS the install, so that question now belongs to npm_range_h2, which asks the
  offline npm-semver ledger rather than deciding for itself.

WHAT REMAINS

  Parse, order (including prereleases), render, canonicalise a package name, and detect
  disagreement between sources. The comparison fixtures are the ordering chain published
  in the SemVer specification - an oracle written by someone else, which is the only
  kind this project accepts after producing an expected value from the code under test
  six separate times. The ordering is additionally checked against npm's own sort of
  every version in the corpus, so agreement is no longer with myself.

    python semver_h2.py --self-test
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / 'schemas' / 'H2_SEMVER_FIXTURES.json'

# major.minor.patch, optional -prerelease, optional +build; a leading v is tolerated
# because registries print it, and everything else is unparseable ON PURPOSE.
_SEMVER = re.compile(
    r'^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)'
    r'(?:-(?P<pre>[0-9A-Za-z.-]+))?'
    r'(?:\+(?P<build>[0-9A-Za-z.-]+))?$')

def parse(version):
    """(major, minor, patch, prerelease-tuple) or None if it is not a version.

    None is a real answer: "1.x", "latest" and "" are not versions, and the protocol
    sends them to untraceable_or_invalid rather than guessing.
    """
    if not isinstance(version, str):
        return None
    m = _SEMVER.match(version.strip())
    if not m:
        return None
    pre = m.group('pre')
    # build metadata is deliberately dropped: SemVer says it takes no part in ordering
    return (int(m.group('major')), int(m.group('minor')), int(m.group('patch')),
            tuple(pre.split('.')) if pre else ())


def _pre_key(identifiers):
    """Ordering key for prerelease identifiers, per the SemVer rules.

    Numeric identifiers compare numerically and rank BELOW alphanumeric ones; a longer
    prerelease outranks a shorter one when every earlier field is equal.
    """
    key = []
    for part in identifiers:
        if part.isdigit():
            key.append((0, int(part), ''))
        else:
            key.append((1, 0, part))
    return key


def sort_key(parsed):
    """A total order over parsed versions. A release outranks its own prereleases."""
    major, minor, patch, pre = parsed
    # 1 for a release, 0 for a prerelease: 1.0.0-rc.1 < 1.0.0
    return (major, minor, patch, 1 if not pre else 0, _pre_key(pre))


def compare(left, right):
    """-1, 0, 1 - or None if either side is not a version."""
    a, b = parse(left), parse(right)
    if a is None or b is None:
        return None
    ka, kb = sort_key(a), sort_key(b)
    return (ka > kb) - (ka < kb)


def render(parsed):
    """The canonical spelling of a parsed version - what a caller should act on."""
    major, minor, patch, pre = parsed
    base = f'{major}.{minor}.{patch}'
    return f'{base}-{".".join(pre)}' if pre else base


def conflicting_candidate_sets(by_source):
    """Do two sources disagree about the fixed versions for one package?

    This is where ambiguity actually lives. Two spellings of one version are not a
    disagreement; two sources naming different version SETS are. Compared on canonical
    forms so `v1.3.0` and `1.3.0` count as agreement, and unparseable values are kept
    as themselves so a source cannot hide a disagreement behind a string this module
    declines to order.
    """
    seen = {}
    for source, versions in (by_source or {}).items():
        canon = frozenset(render(parse(v)) if parse(v) else f'<unparseable:{v}>'
                          for v in versions or [])
        if canon:
            seen[source] = canon
    return len(set(seen.values())) > 1


def canonical_npm_package(name):
    """The package identity the evaluation ledger is keyed on.

    R30a-P0: package name, fixed version and provenance must land on the SAME package.
    Without one spelling of "the same package", `@Scope/Pkg`, `%40scope%2fpkg` and
    `pkg:npm/@scope/pkg` are three packages, and evidence about one gets credited to
    another.
    """
    if not isinstance(name, str):
        return None
    value = name.strip()
    if value.lower().startswith('pkg:npm/'):
        value = value[len('pkg:npm/'):]
    value = value.split('?')[0].split('#')[0]          # drop purl qualifiers
    value = value.replace('%2F', '/').replace('%2f', '/')
    value = value.replace('%40', '@')
    return value.lower() or None


# ---------------------------------------------------------------------------

def self_test():
    doc = json.loads(FIXTURES.read_text(encoding='utf-8'))
    ok = True

    bad = [c for c in doc['parse']
           if (parse(c['version']) is not None) != c['parseable']]
    print(f'  [{"PASS" if not bad else "FAIL"}] parse: '
          f'{len(doc["parse"]) - len(bad)}/{len(doc["parse"])}')
    for c in bad:
        print(f'      {c["version"]!r}: expected parseable={c["parseable"]}')
    ok &= not bad

    bad = [c for c in doc['compare'] if compare(c['left'], c['right']) != c['expected']]
    print(f'  [{"PASS" if not bad else "FAIL"}] compare (SemVer spec ordering): '
          f'{len(doc["compare"]) - len(bad)}/{len(doc["compare"])}')
    for c in bad:
        print(f'      {c["left"]} vs {c["right"]}: expected {c["expected"]}, '
              f'got {compare(c["left"], c["right"])}')
    ok &= not bad

    bad = [c for c in doc['canonical_package']
           if canonical_npm_package(c['raw']) != c['canonical']]
    print(f'  [{"PASS" if not bad else "FAIL"}] canonical_npm_package: '
          f'{len(doc["canonical_package"]) - len(bad)}/{len(doc["canonical_package"])}')
    for c in bad:
        print(f'      {c["raw"]!r}: expected {c["canonical"]!r}, '
              f'got {canonical_npm_package(c["raw"])!r}')
    ok &= not bad

    bad = [c for c in doc['conflicting_candidate_sets']
           if conflicting_candidate_sets(c['by_source']) != c['conflict']]
    n = len(doc['conflicting_candidate_sets'])
    print(f'  [{"PASS" if not bad else "FAIL"}] conflicting_candidate_sets: '
          f'{n - len(bad)}/{n}')
    for c in bad:
        print(f'      {c["by_source"]}: expected conflict={c["conflict"]}')
    ok &= not bad

    # a property no fixture can encode: the order must be total and transitive on the
    # spec's own chain
    chain = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta',
             '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0']
    strict = all(compare(chain[i], chain[i + 1]) == -1 for i in range(len(chain) - 1))
    print(f'  [{"PASS" if strict else "FAIL"}] the spec prerelease chain is strictly '
          f'increasing end to end')
    ok &= strict

    # Agreement with npm itself, on every version this corpus holds rather than on the
    # handful a fixture can carry. The decision ledger was produced by npm's semver, so
    # this is the check that stops `compare` quietly disagreeing with the tool whose
    # answers the experiment will report.
    decisions = ROOT / 'schemas' / 'H2_RANGE_DECISIONS.json'
    if decisions.exists():
        led = json.loads(decisions.read_text(encoding='utf-8'))
        checked, wrong = 0, []
        for pkg, entry in led['sorts'].items():
            ordered = entry['ordered']
            for i in range(len(ordered) - 1):
                checked += 1
                if compare(ordered[i], ordered[i + 1]) == 1:
                    wrong.append((pkg, ordered[i], ordered[i + 1]))
        print(f'  [{"PASS" if not wrong else "FAIL"}] ordering agrees with npm semver '
              f'on {checked:,} adjacent corpus versions ({len(led["sorts"]):,} packages)')
        for w in wrong[:5]:
            print(f'      {w[0]}: npm puts {w[1]} before {w[2]}, this module disagrees')
        ok &= not wrong
    else:
        print('  [FAIL] no decision ledger - cannot check ordering against npm')
        ok = False

    print(f'SEMVER SELF-TEST: {"PASS" if ok else "FAIL"}')
    return 0 if ok else 1


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        sys.exit(self_test())
    print(__doc__)
    sys.exit(0)
