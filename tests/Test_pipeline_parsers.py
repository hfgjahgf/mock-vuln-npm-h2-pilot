"""The pipeline's own unit + mutation gate. Runs offline, no network, no Node.

The parsers in `run_environment.py` are the largest unverified assumption in R37: they
were written from documentation, and a scanner whose output shape differs by one key
would be parsed into confident silence. This pins the shapes as fixtures and then
mutates them to prove each check can fail.

R37c widened the fixtures from simplified shapes to the real tool forms a review named.
R37d added what was still claimed but not covered, and then the local pre-check against
real npm 10.9.3 output added one more shape the documentation had not suggested: a `via`
list of bare package-name strings. R37d added: a `limit` terminator, versions sitting
exactly ON each boundary, per-scanner exit codes with their error bodies, and the
`fixAvailable: true` resolution path. The previous docstring said `limit` was covered
when no fixture contained one.

    python Test_pipeline_parsers.py
    python Test_pipeline_parsers.py --self-test

Nothing here talks to a registry or a scanner. If the real shapes differ from these
fixtures, THE FIXTURES AND THE PARSER CHANGE, never the criteria (protocol §5.3b).
"""
import base64
import gzip
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
import run_environment as RE          # noqa: E402

# --------------------------------------------------------------------- fixtures

# Titles here are PROSE, as they are in real npm audit output - the advisory id lives in
# `url` (347/347 `via` dicts across both R37e pre-check runs) and the CVEs in `cve`.
# The earlier fixture put ids in the titles, which no real report does, and that is why
# reading titles looked harmless (R37f-P0).
NPM_AUDIT = {
    'auditReportVersion': 2,
    'vulnerabilities': {
        'left-pad': {
            'name': 'left-pad', 'severity': 'high',
            'via': [{'source': 1234, 'name': 'left-pad',
                     'title': 'left-pad pads incorrectly on very long input',
                     'url': 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
                     'cve': ['CVE-2026-0001'], 'range': '<1.3.0'},
                    # The shape that caused R37f-P0: a follow-up advisory whose title
                    # CITES the advisory it incompletely fixes, with its own `cve` null.
                    {'source': 1235, 'name': 'left-pad',
                     'title': 'left-pad still pads incorrectly '
                              '(incomplete fix for CVE-2026-9999)',
                     'url': 'https://github.com/advisories/GHSA-incomplete-fix',
                     'cve': None, 'range': '<1.4.0'}],
            'range': '<1.3.0',
            'fixAvailable': {'name': 'left-pad', 'version': '2.0.0',
                             'isSemVerMajor': True},
        },
        # npm's THIRD form: a fix exists and plain `npm audit fix` performs it, but no
        # version is named here. Treating this as "no recommendation" loses a real arm
        # answer (R37c-P0).
        'simple-fix-pkg': {
            'name': 'simple-fix-pkg',
            'via': [{'source': 7, 'title': 'prototype pollution in simple-fix-pkg',
                     'url': 'https://github.com/advisories/GHSA-1111-2222-3333'}],
            'fixAvailable': True,
        },
        'no-fix-pkg': {
            'name': 'no-fix-pkg',
            'via': [{'source': 5, 'title': 'no-fix-pkg leaks memory',
                     'url': 'https://github.com/advisories/GHSA-zzzz-zzzz-zzzz'}],
            'fixAvailable': False,
        },
        # Real shape from the local pre-check (parse-server): `via` is a list of bare
        # package-name STRINGS - "vulnerable through this dependency". No advisory id
        # lives here; it lives on the named package's own entry.
        'transitively-vulnerable': {
            'name': 'transitively-vulnerable',
            'via': ['left-pad'],
            'fixAvailable': True,
        },
    },
}

OSV_SCANNER = {
    # v2.2.4 emits this alongside `results`; it carries no findings and is ignored.
    # Confirmed against the real binary in the R37e pre-check, 29/29 outputs.
    'experimental_config': {},
    'results': [{
        'source': {'path': '/tmp/package-lock.json', 'type': 'lockfile'},
        'packages': [{
            'package': {'name': 'left-pad', 'version': '1.0.1', 'ecosystem': 'npm'},
            # v2 groups the findings it considers one issue; the fix is read from
            # `affected` ranges, never from here.
            'groups': [{'ids': ['GHSA-aaaa-bbbb-cccc'], 'max_severity': '7.5'}],
            'vulnerabilities': [
                {
                    'id': 'GHSA-aaaa-bbbb-cccc',
                    'aliases': ['CVE-2026-0001'],
                    'affected': [{
                        'package': {'name': 'left-pad', 'ecosystem': 'npm'},
                        'ranges': [{
                            'type': 'SEMVER',
                            # TWO segments in ONE range - the schema allows this and the
                            # install sits in the FIRST one.
                            'events': [{'introduced': '1.0.0'}, {'fixed': '1.0.2'},
                                       {'introduced': '3.0.0'}, {'fixed': '3.2.5'}],
                        }],
                    }],
                },
                {
                    # Same package, different advisory: must not answer for the first.
                    'id': 'GHSA-dddd-eeee-ffff', 'aliases': [],
                    'affected': [{
                        'package': {'name': 'left-pad', 'ecosystem': 'npm'},
                        'ranges': [{'type': 'SEMVER',
                                    'events': [{'introduced': '0.0.0'},
                                               {'fixed': '9.9.9'}]}],
                    }],
                },
                {
                    # Closed by `last_affected`: affected, but NO fix is named.
                    'id': 'GHSA-last-affected', 'aliases': ['CVE-2026-0009'],
                    'affected': [{
                        'package': {'name': 'left-pad', 'ecosystem': 'npm'},
                        'ranges': [{'type': 'ECOSYSTEM',
                                    'events': [{'introduced': '1.0.0'},
                                               {'last_affected': '1.5.0'}]}],
                    }],
                },
                {
                    # Closed by `limit`: bounds the range but names no fix either.
                    'id': 'GHSA-limit', 'aliases': ['CVE-2026-0011'],
                    'affected': [{
                        'package': {'name': 'left-pad', 'ecosystem': 'npm'},
                        'ranges': [{'type': 'SEMVER',
                                    'events': [{'introduced': '1.0.0'},
                                               {'limit': '2.0.0'}]}],
                    }],
                },
                {
                    # One advisory covering SIBLING packages - 20 such entries in the
                    # R37e pre-check (@dicebear/core with @dicebear/initials,
                    # react-router-dom with react-router, three @opentelemetry/*). The
                    # sibling's range names a different, higher fix; answering with it
                    # would install a version of a package nobody asked about.
                    'id': 'GHSA-sibling', 'aliases': ['CVE-2026-0012'],
                    # `related` carries CGA- ids in the real output (91 of them). Under
                    # the frozen identity policy `related` is NOT an identity claim
                    # (R26-F4), so nothing here may reach the method gate.
                    'related': ['CGA-rrrr-ssss-tttt'],
                    'affected': [
                        {'package': {'name': 'left-pad', 'ecosystem': 'npm',
                                     'purl': 'pkg:npm/left-pad'},
                         'database_specific': {'source': 'https://example/osv'},
                         'ranges': [{'type': 'SEMVER',
                                     'events': [{'introduced': '1.0.0'},
                                                {'fixed': '1.0.2'}]}]},
                        {'package': {'name': 'left-pad-extra', 'ecosystem': 'npm',
                                     'purl': 'pkg:npm/left-pad-extra'},
                         'ranges': [{'type': 'SEMVER',
                                     'events': [{'introduced': '1.0.0'},
                                                {'fixed': '7.7.7'}]}]},
                    ],
                    'severity': [{'type': 'CVSS_V4', 'score': 'CVSS:4.0/AV:N'}],
                },
                {
                    # GIT ranges hold commit hashes - not comparable to an npm version.
                    'id': 'GHSA-git-range', 'aliases': ['CVE-2026-0010'],
                    'affected': [{
                        'package': {'name': 'left-pad', 'ecosystem': 'npm'},
                        'ranges': [{'type': 'GIT', 'repo': 'https://x/y',
                                    'events': [{'introduced': 'abc123'},
                                               {'fixed': 'def456'}]}],
                    }],
                },
            ],
        }],
    }],
}


class FakeSemver:
    """Range logic stays npm's; this only replays it for the fixture shapes."""

    TABLE = {
        ('1.0.1', '>=1.0.0 <1.0.2'): True,
        ('1.0.1', '>=3.0.0 <3.2.5'): False,
        ('1.0.1', '>=0.0.0 <9.9.9'): True,
        # last_affected closes INCLUSIVELY, limit and fixed exclusively.
        ('1.0.1', '>=1.0.0 <=1.5.0'): True,
        ('1.0.1', '>=1.0.0 <2.0.0'): True,
        # The boundary cases the review asked for: a version sitting exactly on each
        # terminator.
        ('1.5.0', '>=1.0.0 <=1.5.0'): True,     # last_affected: still affected
        ('1.5.0', '>=1.0.0 <1.5.0'): False,     # what the old code asked instead
        ('1.0.2', '>=1.0.0 <1.0.2'): False,     # fixed: no longer affected
        ('2.0.0', '>=1.0.0 <2.0.0'): False,     # limit: outside
        # The SIBLING package's own range. The parser never asks this, because it
        # filters by package name first - but it has to be answerable, or removing the
        # filter would yield no candidate and the mutation could not fail the check.
        ('1.0.1', '>=1.0.0 <7.7.7'): True,
    }

    def satisfies(self, version, expression):
        return self.TABLE.get((version, expression))

    def max_version(self, versions):
        return sorted(versions)[-1] if versions else None


def scans(npm=None, osv=None, npm_status='ok', osv_status='ok'):
    return {'npm_audit': {'status': npm_status,
                          'parsed': npm if npm is not None else NPM_AUDIT},
            'osv_scanner': {'status': osv_status,
                            'parsed': osv if osv is not None else OSV_SCANNER}}


# ----------------------------------------------------------------------- checks

def check_npm_identifiers(art):
    v = []
    got = RE.ids_from_npm_audit(art['npm'])
    for want in ('GHSA-aaaa-bbbb-cccc', 'CVE-2026-0001', 'GHSA-zzzz-zzzz-zzzz'):
        if want not in got:
            v.append(f'npm audit identifier {want} not recovered from {got}')
    # A string `via` names a package, not an advisory: nothing may be invented from it,
    # and it must not break the walk over the entries that DO carry ids.
    if 'left-pad' in got:
        v.append('a package name from a string `via` was treated as an advisory id')
    return {'violations': v, 'ok': not v}


def check_osv_identifiers(art):
    v = []
    got = RE.ids_from_osv(art['osv'])
    for want in ('GHSA-aaaa-bbbb-cccc', 'CVE-2026-0001', 'GHSA-dddd-eeee-ffff'):
        if want not in got:
            v.append(f'osv identifier {want} not recovered from {got}')
    return {'violations': v, 'ok': not v}


def check_npm_three_forms(art):
    """`true`, `false` and the object form are three different answers (R37c-P0)."""
    v = []
    obj = RE.npm_audit_recommendation(scans(npm=art['npm']), 'left-pad')
    if obj['version'] != '2.0.0' or not obj.get('is_semver_major'):
        v.append(f'object form mis-read: {obj}')
    false = RE.npm_audit_recommendation(scans(npm=art['npm']), 'no-fix-pkg')
    if false['version'] is not None or not false.get('tool_says_no_fix'):
        v.append(f'"fixAvailable: false" mis-read: {false}')
    # `true` must be recognised as a fix that exists, and marked for resolution -
    # never silently collapsed into "no recommendation".
    true = RE.npm_audit_recommendation(scans(npm=art['npm']), 'simple-fix-pkg')
    if not true.get('resolved_via_audit_fix'):
        v.append(f'"fixAvailable: true" was not treated as a real fix: {true}')
    if true.get('tool_says_no_fix'):
        v.append('"fixAvailable: true" was recorded as the tool saying there is no fix')
    return {'violations': v, 'ok': not v}


def check_osv_segments(art):
    """The fix comes from the segment the install is in, not the last pair of events."""
    v = []
    rec = RE.osv_recommendation(scans(osv=art['osv']), 'left-pad', '1.0.1',
                                ['GHSA-aaaa-bbbb-cccc'], FakeSemver())
    if rec['version'] != '1.0.2':
        v.append(f"expected 1.0.2 from segment [1.0.0,1.0.2), got {rec['version']}")
    picked = {c['advisory'] for c in rec.get('candidates') or []}
    if 'GHSA-dddd-eeee-ffff' in picked:
        v.append('a different advisory on the same package was answered')
    # The raw segment walk, independent of the recommendation path.
    segs = RE.segments([{'introduced': '1.0.0'}, {'fixed': '1.0.2'},
                        {'introduced': '3.0.0'}, {'fixed': '3.2.5'}])
    if segs != [('1.0.0', '1.0.2', 'fixed'), ('3.0.0', '3.2.5', 'fixed')]:
        v.append(f'segment walk produced {segs}')
    return {'violations': v, 'ok': not v}


def _range(art, vuln_id):
    """The first range of a fixture vulnerability, or None if a mutation removed it.

    Returns rather than raises: a mutation aimed at one check must not crash the others.
    A check may report a violation; it may not take the harness down with it.
    """
    for pkg in art['osv']['results'][0]['packages']:
        for vuln in pkg['vulnerabilities']:
            if vuln['id'] == vuln_id:
                return (vuln.get('affected') or [{}])[0].get('ranges', [None])[0]
    return None


def check_osv_terminators(art):
    """`last_affected`, `limit` and GIT: none of them is a fix.

    Reads the ranges out of the FIXTURE rather than restating them here: a check that
    builds its own input cannot be reached by a mutation of the fixture, which is how
    the first version of this let a relabelled `last_affected` through.
    """
    v = []
    for vuln_id, label in (('GHSA-last-affected', 'last_affected'),
                           ('GHSA-limit', 'limit')):
        rng = _range(art, vuln_id)
        if rng is None:
            v.append(f'the {label} fixture vanished')
            continue
        notes = []
        got = RE.fix_for_range(rng, '1.0.1', FakeSemver(), notes)
        if got is not None:
            v.append(f'a segment closed by {label} reported {got!r} as a fix')
        if not any('segment_without_fix' in n for n in notes):
            v.append(f'no note recorded for a segment closed by {label}')
    notes = []
    git = RE.fix_for_range(_range(art, 'GHSA-git-range') or {'type': 'GIT'},
                           '1.0.1', FakeSemver(), notes)
    if git is not None:
        v.append(f'a GIT range was compared against an npm version: {git}')
    if not any('range_type_not_comparable' in n for n in notes):
        v.append('no note recorded for an incomparable range type')
    return {'violations': v, 'ok': not v}


def check_terminator_boundaries(art):
    """A version sitting exactly ON a terminator (R37d-P1).

    `last_affected` names the last version that IS affected, so its boundary is
    inclusive; `fixed` and `limit` name the first version that is not. Treating all
    three as exclusive put a boundary version outside its own affected segment.
    """
    v = []
    # 1.5.0 is last_affected: it must still be judged INSIDE the segment, which shows
    # up as the "affected but no fix named" note rather than a silent miss.
    last = _range(art, 'GHSA-last-affected')
    if last is None:
        v.append('the last_affected fixture vanished')
    else:
        notes = []
        RE.fix_for_range(last, '1.5.0', FakeSemver(), notes)
        if not any('segment_without_fix' in n for n in notes):
            v.append('a version exactly on last_affected fell outside its own segment')
        if any('semver_undecidable' in n for n in notes):
            v.append(f'the boundary expression was unanswerable: {notes}')
    # 1.0.2 is the `fixed` version: it must be OUTSIDE, so no fix is returned for it.
    multi = _range(art, 'GHSA-aaaa-bbbb-cccc')
    if multi is not None:
        notes = []
        got = RE.fix_for_range(multi, '1.0.2', FakeSemver(), notes)
        if got is not None:
            v.append(f'a version equal to `fixed` was still treated as affected: {got}')
    return {'violations': v, 'ok': not v}


class _Store:
    def keep_result(self, kind, result):
        return 'x' * 64


def check_scanner_exit_codes(art):
    """A parseable body is not a successful scan (R37d-P0).

    osv-scanner uses 0/1 for a completed scan, 127 for a usage error and 128 for
    "nothing scannable"; npm audit uses 1 for "found vulnerabilities" but also prints a
    JSON `error` object when the registry call fails.
    """
    v = []
    cases = [
        ('osv_scanner', 127, '{"error":"unknown flag"}', 'scanner_error'),
        ('osv_scanner', 128, '{"results":[]}', 'no_scannable_packages'),
        ('osv_scanner', 0, '{"results":[]}', 'ok'),
        ('osv_scanner', 1, '{"results":[{"packages":[]}]}', 'ok'),
        ('osv_scanner', 0, 'not json at all', 'output_unparseable'),
        ('npm_audit', 1, '{"error":{"code":"ENETUNREACH"}}', 'output_unparseable'),
        ('npm_audit', 1, '{"auditReportVersion":2,"vulnerabilities":{}}', 'ok'),
        ('npm_audit', 3, '{"auditReportVersion":2,"vulnerabilities":{}}',
         'scanner_error'),
    ]
    for kind, code, body, want in cases:
        got = RE.scan_record({'argv': [kind], 'exit_code': code, 'stdout': body,
                              'stderr': ''}, _Store(), kind)['status']
        if got != want:
            v.append(f'{kind} exit={code} body={body[:28]!r} -> {got}, expected {want}')
    return {'violations': v, 'ok': not v}


def check_audit_fix_reads_the_lockfile(art):
    """`fixAvailable: true` is resolved from the lockfile, not from node_modules.

    The fix is applied with --package-lock-only, so there is no node_modules; a plain
    `npm ls` then reports `missing` and exits 1. Reproduced on the pinned toolchain.
    """
    v = []
    src = Path(RE.__file__).read_text(encoding='utf-8')
    body = src.split('def resolve_audit_fix')[1].split('\ndef ')[0]
    if "'--package-lock-only', '--all', '--json'" not in body:
        v.append('resolve_audit_fix calls npm ls without --package-lock-only, which '
                 'reports `missing` when the fix was applied lockfile-only')
    if 'version_from_lockfile' not in body:
        v.append('there is no fallback to reading the rewritten lockfile')
    return {'violations': v, 'ok': not v}


def check_outcome_is_not_a_verdict(art):
    """The runner records what it did; whether it worked is the ingest's call."""
    v = []
    src = Path(RE.__file__).read_text(encoding='utf-8')
    if "'outcome': 'remediated'" in src:
        v.append("the runner still labels an attempt 'remediated' before anything has "
                 'read the re-scan')
    if "'outcome': 'installed_and_rescanned'" not in src:
        v.append('the neutral outcome label is missing')
    return {'violations': v, 'ok': not v}


def check_scanner_error_is_not_clean(art):
    """A scanner that could not run must not read as a scanner that found nothing."""
    v = []
    env = {'queries': [{'entity_id': 'E1',
                        'target_advisory_identifiers': ['CVE-2026-0001']}]}
    broken = RE.detection(env, scans(npm_status='scanner_error', npm=None,
                                     osv_status='output_unparseable', osv=None))
    cell = broken['per_query']['E1']
    for name in ('npm_audit', 'osv_scanner'):
        if cell[name]['matched'] is not None:
            v.append(f'{name}: a failed scanner reported a verdict')
        if cell[name]['status'] == 'ok':
            v.append(f'{name}: failure was recorded as ok')
    if cell['any_scanner']['usable_scanners'] != 0:
        v.append('the auxiliary union counted unusable scanners')
    clean = RE.detection(env, scans(npm={'vulnerabilities': {}}, osv={'results': []}))
    if clean['per_query']['E1']['npm_audit']['matched'] != []:
        v.append('a clean scan did not report an empty match list')
    # And the two must be distinguishable.
    if broken['per_query']['E1']['npm_audit'] == clean['per_query']['E1']['npm_audit']:
        v.append('scanner failure and a clean scan are still indistinguishable')
    return {'violations': v, 'ok': not v}


def check_scanners_not_merged(art):
    v = []
    env = {'queries': [{'entity_id': 'E1',
                        'target_advisory_identifiers': ['GHSA-aaaa-bbbb-cccc']}]}
    out = RE.detection(env, scans(npm={'vulnerabilities': {}}, osv=art['osv']))
    cell = out['per_query']['E1']
    if cell['npm_audit']['matched']:
        v.append('npm audit reported a match it did not make')
    if not cell['osv_scanner']['matched']:
        v.append('osv-scanner match was lost')
    if 'not a criterion' not in cell['any_scanner'].get('note', ''):
        v.append('any_scanner does not declare itself non-criterial')
    return {'violations': v, 'ok': not v}


def check_install_gate(art):
    """Every step must be required, and npm ls exiting non-zero must fail it."""
    v = []
    full = {k: True for k in ('lockfile_constructable',
                              'install_pass_scripts_suppressed',
                              'dependency_resolution_pass', 'target_version_present')}
    if not RE.gate_passed(full):
        v.append('the gate rejects a fully passing install')
    for missing in list(full):
        broken = dict(full)
        broken[missing] = False
        if RE.gate_passed(broken):
            v.append(f'the gate passes with {missing} failing')
    src = (Path(RE.__file__).read_text(encoding='utf-8'))
    if "listed['exit_code'] == 0" not in src:
        v.append('the gate does not require npm ls to exit 0 - a broken tree still '
                 'prints JSON')
    if 'problems' not in src:
        v.append('the gate ignores npm ls `problems`')
    return {'violations': v, 'ok': not v}


def check_osv_v2_invocation(art):
    """osv-scanner v2 needs the `scan` subcommand; the v1 flag form is not valid."""
    v = []
    src = Path(RE.__file__).read_text(encoding='utf-8')
    if "'osv-scanner', 'scan'" not in src:
        v.append('osv-scanner is invoked without the v2 `scan` subcommand')
    return {'violations': v, 'ok': not v}


def check_exact_pin(art):
    """save-prefix must not widen the fixture's version behind our back."""
    v = []
    if '--save-exact' not in RE.PIN_FLAGS:
        v.append('installs do not pass --save-exact, so ^ may be saved instead')
    src = Path(RE.__file__).read_text(encoding='utf-8')
    if 'pinned_exactly' not in src:
        v.append('the resulting package.json is never verified against the version asked')
    return {'violations': v, 'ok': not v}


def check_arm_names_and_nvd(art):
    v = []
    if RE.ARM_NPM != 'npm_registry_audit_live':
        v.append(f'the npm arm is named {RE.ARM_NPM}, which overstates it as GHSA')
    if RE.ARM_NVD in RE.OPERATIONAL_ARMS:
        v.append('NVD is inside the operational arms and would enter denominators')
    return {'violations': v, 'ok': not v}


def check_failure_classes(art):
    v = []
    table = {
        'npm ERR! ERESOLVE could not resolve': 'peer_dependency',
        'npm ERR! notarget No matching version found': 'version_not_found',
        'npm ERR! network ECONNRESET': 'registry_error',
        # Verbatim from the R37e pre-check, openlearnx@2.0.2 on npm 10.9.3. A published
        # manifest can name `link:`/`file:`/`workspace:` dependencies that only resolve
        # inside the author's tree; that is a fact about the package, not about us, and
        # merging it into `other` would hide it among genuinely unknown failures.
        'npm error code EUNSUPPORTEDPROTOCOL\n'
        'npm error Unsupported URL Type "link:": link:@/components/ui/card':
            'unsupported_dependency_protocol',
        'something else entirely': 'other',
    }
    for blob, want in table.items():
        got = RE.classify_failure({'stderr': blob, 'stdout': ''})
        if got != want:
            v.append(f'{blob[:48]!r} classified {got}, expected {want}')
    return {'violations': v, 'ok': not v}


def check_title_is_not_identity(art):
    """An advisory title is prose, and prose cites other advisories (R37f-P0).

    GHSA-8gc5-j5rx-235r is titled "... (incomplete fix for CVE-2026-26278)" with its own
    `cve` field null. Harvesting the title made npm audit appear to still report
    CVE-2026-26278 at fast-xml-parser@5.3.6 after it had been cleared - 2 of 39 attempts
    in the R37e pre-check, and the two scanners then disagreed for no other reason.

    The citation is real information and is kept, in a field that cannot be mistaken for
    a finding.
    """
    v = []
    ids = RE.ids_from_npm_audit(art['npm'])
    cited = RE.textual_references_from_npm_audit(art['npm'])
    if 'CVE-2026-9999' in ids:
        v.append('a CVE cited in a title was counted as an advisory npm audit reported')
    if 'CVE-2026-9999' not in cited:
        v.append('the title citation was dropped instead of recorded as a reference')
    # The advisory doing the citing must still be identified, from its own url.
    if 'GHSA-incomplete-fix' not in ids:
        v.append('dropping titles also dropped the advisory that carries them')
    if set(ids) & set(cited):
        v.append('an identifier is reported as both a claim and a mere citation')
    return {'violations': v, 'ok': not v}


def check_audit_fix_carries_a_lockfile(art):
    """`npm audit fix` remediates a TREE; a version number is not that tree (R37f-P0).

    Two failures were live here. A fix that rewrote nothing still yielded the installed
    version, so a failure was scored as a recommendation - and the criterion cannot be
    the exit code, because `npm audit fix` exits 1 whenever vulnerabilities remain,
    including after a successful partial fix. And returning only the top-level version
    discarded every transitive change npm made, so the arm was scored on a tree npm
    never proposed.
    """
    v = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        def stub(changed, exit_code):
            state = {'n': 0}

            def fake_run(cmd, cwd, timeout=300):
                if cmd[:3] == ['npm', 'audit', 'fix']:
                    state['n'] += 1
                    if changed:
                        (work / 'package-lock.json').write_text(
                            json.dumps({'packages': {
                                'node_modules/left-pad': {'version': '1.3.0'},
                                'node_modules/tiny-dep': {'version': '2.0.1'}}}),
                            encoding='utf-8')
                    return {'argv': cmd, 'exit_code': exit_code, 'stdout': '',
                            'stderr': '', 'seconds': 0.0}
                if cmd[:2] == ['npm', 'ls']:
                    ver = '1.3.0' if changed else '1.0.0'
                    return {'argv': cmd, 'exit_code': 0, 'seconds': 0.0, 'stderr': '',
                            'stdout': json.dumps(
                                {'dependencies': {'left-pad': {'version': ver}}})}
                return {'argv': cmd, 'exit_code': 0, 'stdout': '', 'stderr': '',
                        'seconds': 0.0}
            return fake_run

        def baseline():
            RE.write_manifest(work, 'left-pad', '1.0.0')
            (work / 'package-lock.json').write_text(
                json.dumps({'packages': {
                    'node_modules/left-pad': {'version': '1.0.0'}}}), encoding='utf-8')

        # 1. audit fix rewrote nothing, and exited 1. That is no action.
        baseline()
        real, RE.run = RE.run, stub(changed=False, exit_code=1)
        try:
            got = RE.resolve_audit_fix(work, 'left-pad', None)
        finally:
            RE.run = real
        if got['lockfile_changed']:
            v.append('an unchanged lockfile was reported as a remediation')
        if got['lockfile'] is not None:
            v.append('a lockfile was carried although the fix rewrote nothing')

        # 2. audit fix never ran at all - timed out, or the process failed to start.
        #    That is our failure, not npm declining to act.
        baseline()
        real, RE.run = RE.run, stub(changed=False, exit_code=None)
        try:
            got = RE.resolve_audit_fix(work, 'left-pad', None)
        finally:
            RE.run = real
        if got['audit_fix_ran']:
            v.append('a fix that never ran was reported as having run')
        if got['lockfile_changed']:
            v.append('a fix that never ran was reported as a remediation')

        # 3. audit fix rewrote the tree, and exited 1 because something remains. That is
        #    a real partial remediation and must be carried as the lockfile.
        baseline()
        real, RE.run = RE.run, stub(changed=True, exit_code=1)
        try:
            got = RE.resolve_audit_fix(work, 'left-pad', None)
        finally:
            RE.run = real
        if not got['lockfile_changed']:
            v.append('exit code 1 was read as failure although the tree was rewritten')
        if not got['lockfile'] or 'tiny-dep' not in (got['lockfile'] or ''):
            v.append('the transitive change npm made was not carried')
        if got['top_level_version'] != '1.3.0':
            v.append(f"top-level version reported as {got['top_level_version']}")

    # A fix that could not be attempted must not be scored as "no action" (R37g). Real
    # instance: @oneuptime/common@9.5.13 carries a 469 KB tree, and `npm audit fix` there
    # is the kind of call that can exceed its budget.
    with tempfile.TemporaryDirectory() as tmp2:
        work2 = Path(tmp2)
        RE.write_manifest(work2, 'left-pad', '1.0.0')
        (work2 / 'package-lock.json').write_text('{}', encoding='utf-8')

        def timed_out(cmd, cwd, timeout=300):
            if cmd[:3] == ['npm', 'audit', 'fix']:
                return {'argv': cmd, 'exit_code': None, 'stdout': '',
                        'stderr': 'TIMEOUT', 'timed_out': True, 'seconds': 600.0}
            return {'argv': cmd, 'exit_code': 0, 'stdout': '', 'stderr': '',
                    'seconds': 0.0}
        real, RE.run = RE.run, timed_out
        try:
            rec_t = RE.npm_audit_recommendation(
                scans(npm={'auditReportVersion': 2, 'vulnerabilities': {
                    'left-pad': {'name': 'left-pad', 'via': [], 'fixAvailable': True}}}),
                'left-pad', work2, None)
        finally:
            RE.run = real
        if not rec_t.get('remediation_unattemptable'):
            v.append('a timed-out audit fix was not distinguished from "no fix"')
        if rec_t.get('tool_says_no_fix'):
            v.append('a timed-out audit fix was recorded as npm saying there is no fix')

    # The recommendation must expose that lockfile, or process() cannot install it.
    rec = RE.npm_audit_recommendation(scans(npm=art['npm']), 'left-pad')
    if rec.get('version') != '2.0.0':
        v.append('the object form stopped resolving')
    return {'violations': v, 'ok': not v}


def check_sibling_package_not_answered_for(art):
    """One advisory can cover several packages; only this package's range applies.

    Twenty such entries appeared in the R37e pre-check. The sibling's range names a
    higher fix, so dropping the name filter does not fail loudly - it installs a version
    derived from a package that is not in this environment at all.
    """
    v = []
    rec = RE.osv_recommendation(scans(osv=art['osv']), 'left-pad', '1.0.1',
                                ['CVE-2026-0012'], FakeSemver())
    if rec['version'] != '1.0.2':
        v.append(f"sibling-covering advisory answered {rec['version']}, expected 1.0.2")
    for c in rec.get('candidates') or []:
        if c['version'] == '7.7.7':
            v.append("the sibling package's own fix entered this package's candidates")
    return {'violations': v, 'ok': not v}


def check_related_is_not_identity(art):
    """`related` is not an identity claim - the frozen policy says so (R26-F4).

    The real output carries 91 `related` entries, all CGA- ids. If they were folded into
    the identifiers a scanner is credited with, the method gate would quietly start
    counting advisories the scanner never claimed to have found.
    """
    v = []
    got = RE.ids_from_osv(art['osv'])
    for bad in [i for i in got if i.startswith('CGA-')]:
        v.append(f'`related` id {bad} was counted as an identifier the scanner reported')
    if 'CVE-2026-0012' not in got:
        v.append('the advisory carrying `related` lost its own aliases')
    return {'violations': v, 'ok': not v}


def check_lossy_output_keeps_its_bytes(art):
    """A digest of bytes nobody kept cannot be recomputed (R37g-P2).

    `errors='replace'` rewrites invalid UTF-8, so on a lossy decode the stored text is a
    rendering and `stdout_bytes_sha256` has no original to check against - unverifiable
    in exactly the case it exists for. A lossy row must therefore carry the bytes.

    Two different byte sequences can also decode to the SAME replaced text, so dedup must
    key on the bytes when they are lossy, or the second one's original is silently lost.
    """
    v = []
    bad_a = b'{"a": "\xff\xfe"}'
    bad_b = b'{"a": "\xfe\xff"}'
    good = b'{"a": "ok"}'
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'raw.jsonl.gz'
        store = RE.RawStore(path)
        for blob in (good, bad_a, bad_b):
            store.keep_result('probe', {
                'stdout': blob.decode('utf-8', errors='replace'),
                'stdout_raw_bytes': blob, 'argv': ['probe'], 'exit_code': 0,
                'stdout_bytes_sha256': hashlib.sha256(blob).hexdigest(),
                'stdout_decoding_lossy':
                    blob.decode('utf-8', errors='replace').encode('utf-8') != blob})
        store.close()
        with gzip.open(path, 'rt', encoding='utf-8') as fh:
            rows = [json.loads(line) for line in fh]

    lossy = [r for r in rows if r.get('decoding_lossy')]
    clean = [r for r in rows if not r.get('decoding_lossy')]
    if len(lossy) != 2:
        v.append(f'two distinct lossy outputs collapsed into {len(lossy)} row(s)')
    for r in lossy:
        if 'content_b64' not in r:
            v.append('a lossy row kept no bytes, so its byte digest cannot be checked')
            continue
        raw = base64.b64decode(r['content_b64'])
        if hashlib.sha256(raw).hexdigest() != r.get('stdout_bytes_sha256'):
            v.append('the kept bytes do not rehash to the recorded byte digest')
    for r in clean:
        if 'content_b64' in r:
            v.append('a losslessly decoded row was duplicated as base64 for no reason')
    return {'violations': v, 'ok': not v}


def check_unevaluated_pin_is_not_a_pass(art):
    """A pin npm never got to demonstrate must report None, never True.

    `write_manifest` writes the exact version and `declared_range` reads that same file
    back, so on a FAILED install the comparison compares our own input to itself. Both
    openlearnx environments in the R37e pre-check therefore recorded
    `pinned_exactly: True` for an install that resolved nothing at all - one of the four
    install-gate steps of protocol §5.2, reported as passed without being evaluated.

    This check EXECUTES `lockfile_for` with npm stubbed out rather than scanning the
    source, so neither a docstring nor a renamed variable can satisfy it.
    """
    v = []
    cases = [
        ('install failed', 1, None, None),
        ('install ok, manifest still exact', 0, None, True),
        ('install ok, save-prefix widened it', 0, '^1.2.3', False),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for label, code, rewrite, want in cases:
            def fake_run(cmd, cwd, timeout=300, _c=code, _w=rewrite):
                if _w is not None:                 # npm rewriting package.json
                    RE.write_manifest(work, 'left-pad', _w)
                return {'argv': cmd, 'exit_code': _c, 'stdout': '',
                        'stderr': '' if _c == 0 else 'npm error code EBADPLATFORM',
                        'duration_s': 0.0}
            real, RE.run = RE.run, fake_run
            try:
                got = RE.lockfile_for(work, 'left-pad', '1.2.3')['pinned_exactly']
            finally:
                RE.run = real
            if got is not want:
                v.append(f'{label}: pinned_exactly is {got!r}, expected {want!r}')
    return {'violations': v, 'ok': not v}


CHECKS = {
    'npm_identifiers': check_npm_identifiers,
    'osv_identifiers': check_osv_identifiers,
    'npm_three_forms': check_npm_three_forms,
    'osv_segments': check_osv_segments,
    'osv_terminators': check_osv_terminators,
    'terminator_boundaries': check_terminator_boundaries,
    'scanner_exit_codes': check_scanner_exit_codes,
    'audit_fix_reads_the_lockfile': check_audit_fix_reads_the_lockfile,
    'outcome_is_not_a_verdict': check_outcome_is_not_a_verdict,
    'scanner_error_is_not_clean': check_scanner_error_is_not_clean,
    'scanners_not_merged': check_scanners_not_merged,
    'install_gate': check_install_gate,
    'osv_v2_invocation': check_osv_v2_invocation,
    'exact_pin': check_exact_pin,
    'arm_names_and_nvd': check_arm_names_and_nvd,
    'failure_classes': check_failure_classes,
    'sibling_package_not_answered_for': check_sibling_package_not_answered_for,
    'related_is_not_identity': check_related_is_not_identity,
    'title_is_not_identity': check_title_is_not_identity,
    'audit_fix_carries_a_lockfile': check_audit_fix_carries_a_lockfile,
    'lossy_output_keeps_its_bytes': check_lossy_output_keeps_its_bytes,
    'unevaluated_pin_is_not_a_pass': check_unevaluated_pin_is_not_a_pass,
}


def run(art):
    checks = {name: fn(art) for name, fn in CHECKS.items()}
    return {'checks': checks, 'passed': all(c['ok'] for c in checks.values())}


# -------------------------------------------------------------------- mutations

def _f_npm_ids_hidden(a):
    via = a['npm']['vulnerabilities']['left-pad']['via'][0]
    for key in ('title', 'url', 'cve'):
        via.pop(key, None)
    return a


def _f_osv_alias_renamed(a):
    vuln = a['osv']['results'][0]['packages'][0]['vulnerabilities'][0]
    vuln['aliases'] = []
    vuln['id'] = 'OSV-OTHER'
    return a


def _f_osv_first_segment_removed(a):
    """Leave only the branch the install is NOT on."""
    rng = a['osv']['results'][0]['packages'][0]['vulnerabilities'][0][
        'affected'][0]['ranges'][0]
    rng['events'] = [{'introduced': '3.0.0'}, {'fixed': '3.2.5'}]
    return a


def _f_npm_true_becomes_false(a):
    a['npm']['vulnerabilities']['simple-fix-pkg']['fixAvailable'] = False
    return a


def _f_limit_becomes_fixed(a):
    vuln = [v for v in a['osv']['results'][0]['packages'][0]['vulnerabilities']
            if v['id'] == 'GHSA-limit'][0]
    vuln['affected'][0]['ranges'][0]['events'][1] = {'fixed': '2.0.0'}
    return a


def _f_last_affected_becomes_fixed(a):
    vuln = [v for v in a['osv']['results'][0]['packages'][0]['vulnerabilities']
            if v['id'] == 'GHSA-last-affected'][0]
    vuln['affected'][0]['ranges'][0]['events'][1] = {'fixed': '1.5.0'}
    return a


FAULTS = [
    ('npm audit naming the advisory only in fields we do not read',
     _f_npm_ids_hidden, 'npm_identifiers'),
    ('osv naming the advisory under an id we do not match',
     _f_osv_alias_renamed, 'osv_segments'),
    ('the segment containing the install removed from the range',
     _f_osv_first_segment_removed, 'osv_segments'),
    ('"fixAvailable: true" downgraded to "no fix"',
     _f_npm_true_becomes_false, 'npm_three_forms'),
    ('last_affected relabelled as a fix', _f_last_affected_becomes_fixed,
     'osv_terminators'),
    ('limit relabelled as a fix', _f_limit_becomes_fixed, 'osv_terminators'),
]


# Checks that build their own input cannot be reached by mutating a fixture - the
# R37c debt, where `osv_terminators` went un-mutated for exactly this reason. These
# faults patch the module under test instead, and each one is the PREVIOUS behaviour
# restored verbatim, so the mutation proves the fix is what the check is holding.

def _c_pin_compared_unconditionally():
    """R37e-P1 as it stood: compare declared_range to version whatever npm did."""
    real = RE.lockfile_for

    def patched(work, package, version):
        result = real(work, package, version)
        result['pinned_exactly'] = result['declared_range'] == version
        return result

    RE.lockfile_for = patched
    return lambda: setattr(RE, 'lockfile_for', real)


def _c_unsupported_protocol_merged_into_other():
    """R37e-P2 as it stood: EUNSUPPORTEDPROTOCOL indistinguishable from unknown."""
    real = RE.classify_failure

    def patched(result):
        blob = ((result.get('stderr') or '') + (result.get('stdout') or '')).lower()
        if 'eunsupportedprotocol' in blob or 'unsupported url type' in blob:
            return 'other'
        return real(result)

    RE.classify_failure = patched
    return lambda: setattr(RE, 'classify_failure', real)


def _c_sibling_filter_dropped():
    """Answer from every affected entry, not only this package's."""
    real = RE.osv_recommendation
    RE.osv_recommendation = _osv_recommendation_no_name_filter
    return lambda: setattr(RE, 'osv_recommendation', real)


def _osv_recommendation_no_name_filter(scans_, package, installed, targets, semver):
    """`osv_recommendation` with the affected-package name check removed."""
    record = scans_['osv_scanner']
    wanted, candidates, notes = set(targets), [], []
    for res in (record.get('parsed') or {}).get('results', []) or []:
        for pkg in res.get('packages', []) or []:
            if (pkg.get('package') or {}).get('name') != package:
                continue
            for vuln in pkg.get('vulnerabilities', []) or []:
                if not ({vuln.get('id')} | set(vuln.get('aliases') or [])) & wanted:
                    continue
                for affected in vuln.get('affected', []) or []:
                    for rng in affected.get('ranges', []) or []:
                        picked = RE.fix_for_range(rng, installed, semver, notes)
                        if picked:
                            candidates.append({'version': picked,
                                               'advisory': vuln.get('id'),
                                               'range_type': rng.get('type')})
    if not candidates:
        return {'version': None, 'notes': notes, 'source': 'no-filter mutant'}
    return {'version': semver.max_version([c['version'] for c in candidates]),
            'candidates': candidates, 'notes': notes, 'source': 'no-filter mutant'}


def _c_related_folded_into_identity():
    """Credit the scanner with ids it only listed as `related`."""
    real = RE.ids_from_osv

    def patched(parsed):
        out = set(real(parsed))
        for res in (parsed or {}).get('results', []) or []:
            for pkg in res.get('packages', []) or []:
                for vuln in pkg.get('vulnerabilities', []) or []:
                    out.update(vuln.get('related') or [])
        return sorted(out)

    RE.ids_from_osv = patched
    return lambda: setattr(RE, 'ids_from_osv', real)


def _c_titles_scanned_for_ids():
    """R37f-P0 as it stood: harvest identifiers out of advisory prose."""
    real = RE.ids_from_npm_audit

    def patched(parsed):
        out = set(real(parsed))
        for via in RE._via_dicts(parsed):
            for field in ('source', 'url', 'title', 'name'):
                value = via.get(field)
                if isinstance(value, str):
                    out.update(RE._ids_in(value))
        return sorted(out)

    RE.ids_from_npm_audit = patched
    return lambda: setattr(RE, 'ids_from_npm_audit', real)


def _c_audit_fix_returns_a_version():
    """R37f-P0 as it stood: read a version out of the lockfile, changed or not."""
    real = RE.resolve_audit_fix

    def patched(work, package, store):
        out = real(work, package, store)
        return {**out, 'lockfile_changed': True, 'lockfile': None,
                'top_level_version': (out['top_level_version']
                                      or RE.version_from_lockfile(work, package))}

    RE.resolve_audit_fix = patched
    return lambda: setattr(RE, 'resolve_audit_fix', real)


def _c_lossy_bytes_discarded():
    """R37g-P2 as it stood: store the rendered text, keep no bytes, dedup on the text."""
    real = RE.RawStore.keep

    def patched(self, kind, text, meta=None, raw_bytes=None):
        return real(self, kind, text, meta, raw_bytes=None)

    RE.RawStore.keep = patched
    return lambda: setattr(RE.RawStore, 'keep', real)


def _c_audit_fix_failure_is_no_action():
    """R37g as it stood: a fix that never ran fell through to "changed nothing"."""
    real = RE.resolve_audit_fix

    def patched(work, package, store):
        out = real(work, package, store)
        return {**out, 'audit_fix_ran': True}

    RE.resolve_audit_fix = patched
    return lambda: setattr(RE, 'resolve_audit_fix', real)


CODE_FAULTS = [
    ('a remediation that never ran recorded as "npm found nothing to do"',
     _c_audit_fix_failure_is_no_action, 'audit_fix_carries_a_lockfile'),
    ('the bytes behind a lossy decode thrown away',
     _c_lossy_bytes_discarded, 'lossy_output_keeps_its_bytes'),
    ('advisory ids harvested out of prose titles',
     _c_titles_scanned_for_ids, 'title_is_not_identity'),
    ('audit fix reduced to a version number, unchanged tree treated as a fix',
     _c_audit_fix_returns_a_version, 'audit_fix_carries_a_lockfile'),
    ('a pin reported as exact on an install that never ran',
     _c_pin_compared_unconditionally, 'unevaluated_pin_is_not_a_pass'),
    ('an uninstallable published manifest filed under "other"',
     _c_unsupported_protocol_merged_into_other, 'failure_classes'),
    ("a sibling package's fix answered for this package",
     _c_sibling_filter_dropped, 'sibling_package_not_answered_for'),
    ('`related` ids credited to the scanner as findings',
     _c_related_folded_into_identity, 'related_is_not_identity'),
]


def fresh():
    return {'npm': json.loads(json.dumps(NPM_AUDIT)),
            'osv': json.loads(json.dumps(OSV_SCANNER))}


def self_test():
    base = run(fresh())
    print(f"  [{'PASS' if base['passed'] else 'FAIL'}] baseline: the parsers read the "
          f"documented shapes")
    if not base['passed']:
        for name, c in base['checks'].items():
            if not c['ok']:
                print(f'    {name}: {c["violations"][:3]}')
        print('TEST SETUP FAILURE')
        return 1
    caught = 0
    for label, fault, expect in FAULTS:
        got = run(fault(fresh()))
        failing = [n for n, c in got['checks'].items() if not c['ok']]
        if expect in failing:
            caught += 1
            print(f'  [PASS] {label}: caught by {", ".join(failing)}')
        else:
            print(f'  [NOT CAUGHT] {label} (expected {expect}, failing: {failing})')
    for label, patch, expect in CODE_FAULTS:
        restore = patch()
        try:
            got = run(fresh())
        finally:
            restore()
        failing = [n for n, c in got['checks'].items() if not c['ok']]
        if expect in failing:
            caught += 1
            print(f'  [PASS] {label}: caught by {", ".join(failing)}')
        else:
            print(f'  [NOT CAUGHT] {label} (expected {expect}, failing: {failing})')
    total = len(FAULTS) + len(CODE_FAULTS)
    ok = caught == total
    print(f"SELF-TEST: {'PASS' if ok else 'FAIL'}: {caught}/{total} caught")
    return 0 if ok else 1


def main():
    if '--self-test' in sys.argv:
        return self_test()
    report = run(fresh())
    for name, c in report['checks'].items():
        print(f"  [{'PASS' if c['ok'] else 'FAIL'}] {name}")
        for line in c['violations'][:6]:
            print(f'         {line}')
    print(f"PIPELINE PARSERS: {'PASS' if report['passed'] else 'FAIL'}")
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
