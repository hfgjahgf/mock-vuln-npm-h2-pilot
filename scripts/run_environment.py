"""One shard of the H2 live census. Runs inside GitHub Actions; touches the network.

  phase 1  pin the package at its installed version, scan with both real scanners, and
           record PER SCANNER whether it named any target advisory (protocol §5.1)
  phase 2  for each arm's recommendation, INSTALL IT FIRST -
             lockfile -> npm ci -> npm ls -> target version in tree
           and only if every step passes, re-scan with BOTH scanners (protocol §5.2)

Nothing here decides anything. It records what the tools said, plus enough raw material
for the offline ingest to classify. Every environment produces exactly one JSON line,
including the ones that fail - "no line" and "failed" must stay distinguishable.

R37d corrected four more, all reproduced with counterexamples: `npm ls` needs
--package-lock-only when the fix was applied that way, a parseable body is not a
successful scan, `last_affected` closes its segment inclusively, and the runner must not
label an attempt `remediated` before anything has read the re-scan.

R37c corrected six things a review reproduced with counterexamples:
  - osv-scanner v2 needs the `scan` subcommand; the v1 flag form silently did nothing
  - `fixAvailable: true` is a REAL npm answer (fix via plain `npm audit fix`), and was
    being turned into "no recommendation"
  - OSV ranges carry several introduced/fixed SEGMENTS; only the last pair was read, so
    a fix in an earlier branch was invisible
  - `npm ls` exits non-zero on a broken tree while still printing JSON, and the gate
    looked only at the JSON
  - a scanner that failed to run was indistinguishable from a scanner that found nothing
  - the pinned version was not pinned in package.json, so save-prefix could widen it

Protocol: H2_REAL_PIPELINE_PROTOCOL.md (h2-real-protocol-5).
"""
import argparse
import datetime
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Named for what they actually are (protocol §2). `npm audit` queries the configured
# registry's audit endpoint, which is backed by the GitHub Advisory Database - calling
# the arm "GHSA" would overstate what is being asked.
ARM_NPM = 'npm_registry_audit_live'
ARM_OSV = 'osv_scanner_live'
ARM_UNIFIED = 'unified_frozen_model'
OPERATIONAL_ARMS = (ARM_NPM, ARM_OSV, ARM_UNIFIED)
# NVD has no off-the-shelf npm scanner. That is a limit of the tool ecosystem, NOT a
# measurement of NVD, so its rows say "not evaluated" and stay out of every denominator.
ARM_NVD = 'nvd'

NO_SCRIPTS = ['--ignore-scripts']
# --save-exact: without it the dependency lands as `^x.y.z` and the fixture is no longer
# the version the ledger names. --audit/--fund off: no extra network, no noise on stdout.
PIN_FLAGS = ['--save-exact', '--audit=false', '--fund=false']
HERE = Path(__file__).resolve().parent
SEMVER_HELPER = HERE / 'semver_check.js'

# OSV range types. GIT ranges cannot be compared to an npm version at all; saying so is
# the honest outcome, guessing is not.
SEMVER_RANGE_TYPES = ('SEMVER', 'ECOSYSTEM')


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def run(cmd, cwd, timeout=300):
    """Run a command, never raise. The tool failing IS data.

    Output is captured as bytes and decoded here rather than by subprocess: decoding is
    pinned to UTF-8 with replacement instead of the platform locale (advisory titles
    carry non-ASCII, and a locale-decoded pipe raised UnicodeDecodeError from INSIDE
    subprocess, which is neither TimeoutExpired nor OSError and would have cost the whole
    environment for an encoding reason - found on a GBK console, 2026-08-17), and holding
    the bytes lets the digest attest what the process wrote rather than what replacement
    turned it into (R37f-P2).

    `started_utc` is the observation time for whichever live database this command asked
    - the registry audit endpoint or osv.dev. Nothing else records when a scan happened.
    """
    started = time.time()
    at = utc_now()
    try:
        # Captured as BYTES and decoded here, so the digest below is over what the
        # process actually wrote (R37f-P2). `errors='replace'` rewrites invalid UTF-8,
        # and hashing the replaced text would attest a string the scanner never emitted.
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout)
        text = p.stdout.decode('utf-8', errors='replace')
        return {'argv': cmd, 'exit_code': p.returncode, 'stdout': text,
                'stderr': p.stderr.decode('utf-8', errors='replace')[-4000:],
                'stdout_bytes_sha256': hashlib.sha256(p.stdout).hexdigest(),
                'stdout_bytes': len(p.stdout),
                # True means the stored text is a lossy rendering and only
                # stdout_bytes_sha256 attests the original.
                'stdout_decoding_lossy': text.encode('utf-8') != p.stdout,
                'started_utc': at, 'seconds': round(time.time() - started, 2)}
    except subprocess.TimeoutExpired:
        return {'argv': cmd, 'exit_code': None, 'stdout': '', 'stderr': 'TIMEOUT',
                'timed_out': True, 'started_utc': at,
                'seconds': round(time.time() - started, 2)}
    except OSError as exc:
        return {'argv': cmd, 'exit_code': None, 'stdout': '',
                'stderr': f'{type(exc).__name__}: {exc}', 'started_utc': at,
                'seconds': round(time.time() - started, 2)}


def as_json(result):
    try:
        return json.loads(result['stdout'])
    except (ValueError, TypeError):
        return None


def sha256(text):
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()


class RawStore:
    """Keeps the bytes that each recorded sha256 was taken over.

    Recording a hash and discarding the bytes leaves a checksum with nothing to check.
    Scanner stdout, the lockfile, and the `npm ls` tree all go in here.

    Two digests, because they answer different questions (R37f-P2). `sha256` is over the
    stored text and is what makes this file self-verifying. `stdout_bytes_sha256` is over
    the bytes the process wrote. They are equal whenever decoding was lossless, which is
    the normal case; when `decoding_lossy` is true the stored text is a rendering and
    only the byte digest attests the original.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = gzip.open(self.path, 'wt', encoding='utf-8')
        self.seen = set()

    def keep(self, kind, text, meta=None):
        digest = sha256(text)
        if digest not in self.seen:
            self.seen.add(digest)
            self.handle.write(json.dumps(
                {'kind': kind, 'sha256': digest, 'content': text or '',
                 'meta': meta or {}}, ensure_ascii=False) + '\n')
        return digest

    def keep_result(self, kind, result):
        return self.keep(kind, result.get('stdout'),
                         {'argv': result.get('argv'),
                          'exit_code': result.get('exit_code'),
                          'started_utc': result.get('started_utc'),
                          'stdout_bytes_sha256': result.get('stdout_bytes_sha256'),
                          'stdout_bytes': result.get('stdout_bytes'),
                          'decoding_lossy': result.get('stdout_decoding_lossy'),
                          'stderr': result.get('stderr')})

    def close(self):
        self.handle.close()


# ------------------------------------------------------------------ npm plumbing

def write_manifest(work, package, version):
    (work / 'package.json').write_text(json.dumps({
        'name': 'h2-fixture', 'version': '1.0.0', 'private': True,
        # Exactly one target instance, at the top level (protocol §3).
        'dependencies': {package: version},
    }, indent=1) + '\n', encoding='utf-8')


def clean(work):
    for stale in ('package-lock.json', 'node_modules'):
        target = work / stale
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
        elif target.exists():
            target.unlink()


def declared_range(work, package):
    """What package.json ended up pinning - save-prefix can widen it behind our back."""
    try:
        manifest = json.loads((work / 'package.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return (manifest.get('dependencies') or {}).get(package)


def lockfile_for(work, package, version):
    """Resolve a lockfile without downloading tarballs or executing anything."""
    write_manifest(work, package, version)
    clean(work)
    result = run(['npm', 'install', f'{package}@{version}',
                  '--package-lock-only', *NO_SCRIPTS, *PIN_FLAGS], work)
    result['declared_range'] = declared_range(work, package)
    # An exact pin is part of the fixture being what it claims to be - but only npm can
    # demonstrate it. write_manifest() already wrote the exact version, so when the
    # install FAILS the manifest still holds our own input and the comparison compares a
    # string to itself: it answered True for both openlearnx environments in the R37e
    # pre-check, whose install never got off the ground. An unevaluated check reports
    # None, never a pass (protocol paragraph 5.2 records four steps, not three-and-a-guess).
    result['pinned_exactly'] = (result['declared_range'] == version
                                if result['exit_code'] == 0 else None)
    return result


def scan_both(work, store, phase):
    """npm audit and osv-scanner over the same lockfile. Both, always, for every arm."""
    lock = work / 'package-lock.json'
    lock_text = lock.read_text(encoding='utf-8') if lock.exists() else ''
    lock_sha = store.keep('package-lock.json', lock_text, {'phase': phase})

    audit = run(['npm', 'audit', '--json'], work)
    # osv-scanner v2 requires the `scan` subcommand; the v1 flag-only form is not a
    # valid v2 invocation and would fail rather than scan.
    osv = run(['osv-scanner', 'scan', '--lockfile', str(lock), '--format', 'json'], work)
    return {
        'lockfile_sha256': lock_sha,
        'npm_audit': scan_record(audit, store, 'npm_audit'),
        'osv_scanner': scan_record(osv, store, 'osv_scanner'),
    }


# Exit codes that mean "the scan ran". Both tools use 1 for "found something", so a
# non-zero code alone is not an error - but neither is a parseable body a success
# (R37d-P0): osv-scanner returns 127 for a usage error and 128 for "nothing scannable",
# and npm audit prints a JSON error object when the registry call fails.
SCAN_OK_EXIT = {'npm_audit': {0, 1}, 'osv_scanner': {0, 1}}
OSV_NO_PACKAGES_EXIT = 128


def scan_record(result, store, kind):
    """A scanner that could not run is not a scanner that found nothing.

    Three things have to agree before a scan counts: the exit code has to be one the
    tool uses for a completed scan, the body has to parse, and the body has to have the
    shape that tool produces on success. Any one of them failing is a different fact
    from "no vulnerabilities", and the ingest must be able to tell them apart.
    """
    parsed = as_json(result)
    code = result.get('exit_code')
    status = 'ok'
    if code is None:
        status = 'scanner_error'
    elif kind == 'osv_scanner' and code == OSV_NO_PACKAGES_EXIT:
        # A distinct condition, not an error and not a clean scan: the scanner found
        # nothing it could scan at all.
        status = 'no_scannable_packages'
    elif code not in SCAN_OK_EXIT[kind]:
        status = 'scanner_error'
    elif parsed is None:
        status = 'output_unparseable'
    elif not valid_payload(kind, parsed):
        status = 'output_unparseable'
    return {'raw_sha256': store.keep_result(kind, result),
            # Over the process's own bytes, not the replacement-decoded text (R37f-P2).
            'stdout_bytes_sha256': result.get('stdout_bytes_sha256'),
            'stdout_decoding_lossy': result.get('stdout_decoding_lossy'),
            # When this live database was asked. Nothing else records it.
            'observed_utc': result.get('started_utc'),
            'exit_code': code, 'status': status,
            'parsed': parsed if status == 'ok' else None,
            'stderr': result.get('stderr') if status != 'ok' else None}


def valid_payload(kind, parsed):
    """The shape each tool emits on a completed scan - an error object is not one."""
    if not isinstance(parsed, dict):
        return False
    if parsed.get('error'):
        # npm audit reports registry failures as a top-level `error` object while still
        # exiting 1, which is otherwise its "found vulnerabilities" code.
        return False
    if kind == 'npm_audit':
        return isinstance(parsed.get('vulnerabilities'), dict) or (
            'auditReportVersion' in parsed)
    return isinstance(parsed.get('results'), list)


# ------------------------------------------------------------------ parsing

def _via_dicts(parsed):
    """`via` entries come in two shapes, both seen in the local pre-check: a dict holding
    the advisory itself, and a bare STRING naming another package this one is vulnerable
    *through*. A string carries no advisory id and none is invented for it - the ids for
    that path live on the named package's own entry, which this loop also visits.
    """
    for entry in ((parsed or {}).get('vulnerabilities') or {}).values():
        for via in entry.get('via', []) or []:
            if isinstance(via, dict):
                yield via


def ids_from_npm_audit(parsed):
    """Advisory identifiers npm audit CLAIMS - this scanner alone (protocol §5.1).

    The advisory's own `url` and its structured `cve`/`aliases` lists, and nothing else.

    `title` is deliberately NOT read (R37f-P0). An advisory title is prose, and prose
    cites other advisories: GHSA-8gc5-j5rx-235r is titled "... (incomplete fix for
    CVE-2026-26278)" while its own `cve` field is null, and a `sharp` advisory is titled
    "inherited vulnerabilities in libvips: CVE-2026-33327, CVE-2026-33328, ..." for CVEs
    belonging to a native C library that is not an npm package at all. Scanning titles
    made npm audit appear to still report the target advisory at fast-xml-parser@5.3.6
    after it had in fact been cleared - the two scanners then disagreed for no reason but
    this. A citation is not a claim of identity; it is recorded separately, by
    textual_references_from_npm_audit, and never reaches the method gate.

    `source` and `name` are not read either: measured over both pre-check runs they
    contributed no identifier that url/cve/aliases did not already carry (347 `via`
    dicts), and `name` is a package name, which must never become an advisory id.
    """
    seen = set()
    for via in _via_dicts(parsed):
        url = via.get('url')
        if isinstance(url, str):
            seen.update(_ids_in(url))
        for cve in via.get('cve', []) or []:
            seen.add(cve)
        for alias in via.get('aliases', []) or []:
            seen.add(alias)
    return sorted(seen)


def textual_references_from_npm_audit(parsed):
    """Identifiers a title MENTIONS that the advisory does not claim to be.

    Display and provenance only - protocol §5.1's method gate reads
    ids_from_npm_audit. Kept because "the title cites the advisory this one incompletely
    fixes" is real information about the ecosystem; discarded from identity because a
    citation is not a claim.
    """
    seen = set()
    for via in _via_dicts(parsed):
        title = via.get('title')
        if isinstance(title, str):
            seen.update(_ids_in(title))
    return sorted(seen - set(ids_from_npm_audit(parsed)))


def ids_from_osv(parsed):
    seen = set()
    for res in (parsed or {}).get('results', []) or []:
        for pkg in res.get('packages', []) or []:
            for vuln in pkg.get('vulnerabilities', []) or []:
                if vuln.get('id'):
                    seen.add(vuln['id'])
                seen.update(vuln.get('aliases') or [])
    return sorted(seen)


def _ids_in(text):
    out = []
    for token in str(text).replace('/', ' ').replace(',', ' ').split():
        token = token.strip('.,)"\'')
        if token.startswith(('CVE-', 'GHSA-', 'OSV-', 'MINI-', 'ROOT-')):
            out.append(token)
    return out


def npm_audit_recommendation(scans, package, work=None, store=None):
    """npm's own answer. `fixAvailable` has THREE forms, not two (R37c-P0).

    true    the fix is whatever plain `npm audit fix` would do - a real recommendation,
            whose version has to be resolved by performing that fix on the lockfile
    false   the tool says there is no automatic fix
    object  a named version, possibly a major upgrade
    """
    record = scans['npm_audit']
    if record.get('status') != 'ok':
        return {'version': None, 'source': 'npm audit', 'unusable': record['status']}
    entry = ((record.get('parsed') or {}).get('vulnerabilities') or {}).get(package) or {}
    fix = entry.get('fixAvailable')
    if isinstance(fix, dict):
        return {'version': fix.get('version'),
                'is_semver_major': bool(fix.get('isSemVerMajor')),
                'source': 'npm audit fixAvailable object'}
    if fix is True:
        applied = resolve_audit_fix(work, package, store) if work else None
        if applied is None:
            return {'version': None, 'source': 'npm audit fixAvailable true',
                    'resolved_via_audit_fix': True, 'unresolved': True}
        if not applied['lockfile_changed']:
            # audit fix ran and rewrote nothing. That is no action, not a fix whose
            # version happens to equal the installed one (R37f-P0).
            return {'version': None,
                    'source': 'npm audit fixAvailable true, audit fix changed nothing',
                    'resolved_via_audit_fix': True, 'tool_says_no_fix': True,
                    'audit_fix_changed_nothing': True,
                    'audit_fix_exit_code': applied['audit_fix_exit_code']}
        # The remediation is the whole lockfile npm wrote; the version is reporting.
        return {'version': applied['top_level_version'],
                'lockfile': applied['lockfile'],
                'manifest': applied['manifest'],
                'lockfile_sha256': applied['lockfile_sha256'],
                'source': 'npm audit fixAvailable true, resolved via audit fix',
                'resolved_via_audit_fix': True,
                'audit_fix_exit_code': applied['audit_fix_exit_code'],
                'unresolved': False}
    if fix is False:
        return {'version': None, 'source': 'npm audit fixAvailable false',
                'tool_says_no_fix': True}
    return {'version': None, 'source': 'npm audit', 'no_entry_for_package': True}


def read_lockfile(work):
    return _read(work / 'package-lock.json')


def _read(path):
    try:
        return path.read_text(encoding='utf-8')
    except OSError:
        return None


def resolve_audit_fix(work, package, store):
    """`fixAvailable: true` names no version - the remediation IS the lockfile.

    npm defines `npm audit fix` as applying remediation to the whole dependency tree,
    and with --package-lock-only the thing it rewrites is package-lock.json. Returning
    only the top-level version and rebuilding a tree from it (R37f-P0) discards every
    transitive change npm made, so the arm was scored on a tree npm never proposed.
    The fixed lockfile is captured here and installed verbatim by attempt().

    The criterion is whether the LOCKFILE CHANGED, not the exit code. `npm audit fix`
    exits 1 whenever vulnerabilities remain afterwards - which includes a successful
    PARTIAL fix - so exit 1 does not mean failure. It also leaves the lockfile untouched
    when it can fix nothing, and reading a version out of that unchanged file returned
    the installed version as though it were a recommendation (reproduced: audit fix
    exit 1, lockfile untouched, resolve_audit_fix returned the installed 1.0.0).

    The fix is applied with --package-lock-only, so there is NO node_modules afterwards
    - and a plain `npm ls` then reports `missing` and exits 1, which is how this branch
    silently produced nothing at all (R37d-P0, reproduced on the pinned Node 22.20.0 /
    npm 10.9.3). `npm ls --package-lock-only` reads the lockfile instead.
    """
    before = read_lockfile(work)
    fixed = run(['npm', 'audit', 'fix', '--package-lock-only', *NO_SCRIPTS,
                 '--fund=false'], work, timeout=600)
    if store is not None:
        store.keep_result('npm_audit_fix', fixed)
    after = read_lockfile(work)
    # audit fix can widen the manifest range as well as rewrite the lockfile, and
    # `npm ci` refuses to run when the two disagree. Both files are the remediation.
    manifest = _read(work / 'package.json')
    listed = run(['npm', 'ls', '--package-lock-only', '--all', '--json'],
                 work, timeout=300)
    if store is not None:
        store.keep_result('npm_ls_after_audit_fix', listed)
    tree = as_json(listed)
    version = (((tree or {}).get('dependencies') or {}).get(package, {}).get('version')
               or version_from_lockfile(work, package))
    changed = after is not None and after != before
    out = {'lockfile': after if changed else None,
           'manifest': manifest if changed else None,
           'lockfile_sha256': sha256(after) if changed else None,
           'top_level_version': version,
           'lockfile_changed': changed,
           'audit_fix_exit_code': fixed.get('exit_code'),
           'audit_fix_lockfile_sha256_before': sha256(before) if before else None}
    if store is not None and changed:
        store.keep('package-lock.json', after, {'phase': 'npm_audit_fix_result'})
        store.keep('package.json', manifest, {'phase': 'npm_audit_fix_result'})
    return out


def version_from_lockfile(work, package):
    try:
        lock = json.loads((work / 'package-lock.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    entry = (lock.get('packages') or {}).get(f'node_modules/{package}') or {}
    return entry.get('version')


def osv_recommendation(scans, package, installed, targets, semver):
    """OSV's fix, bound to the target advisory and the segment containing the install.

    Protocol §5.3b. Ranges carry SEGMENTS - introduced, fixed, introduced, fixed - and
    only the segment the installed version falls in is the one whose `fixed` applies.
    """
    record = scans['osv_scanner']
    if record.get('status') != 'ok':
        return {'version': None, 'source': 'osv-scanner', 'unusable': record['status']}
    wanted = set(targets)
    candidates, notes = [], []
    for res in (record.get('parsed') or {}).get('results', []) or []:
        for pkg in res.get('packages', []) or []:
            if (pkg.get('package') or {}).get('name') != package:
                continue
            for vuln in pkg.get('vulnerabilities', []) or []:
                names = {vuln.get('id')} | set(vuln.get('aliases') or [])
                if not (names & wanted):
                    continue                       # not the advisory we are answering
                for affected in vuln.get('affected', []) or []:
                    name = (affected.get('package') or {}).get('name')
                    if name not in (None, package):
                        continue
                    for rng in affected.get('ranges', []) or []:
                        picked = fix_for_range(rng, installed, semver, notes)
                        if picked:
                            candidates.append({'version': picked,
                                               'advisory': vuln.get('id'),
                                               'range_type': rng.get('type')})
    if not candidates:
        return {'version': None, 'notes': notes,
                'source': 'osv-scanner advisory segment containing the installed '
                          'version'}
    # Several target advisories can apply to one package; the pipeline installs ONE
    # version, so take the highest by SEMVER - never by string order.
    best = semver.max_version([c['version'] for c in candidates])
    return {'version': best, 'candidates': candidates, 'notes': notes,
            'source': 'osv-scanner advisory segment containing the installed version'}


def fix_for_range(rng, installed, semver, notes):
    """Walk the range's events into segments and answer from the containing one.

    OSV events are ordered: each `introduced` opens a segment and the next terminator
    closes it. `fixed` gives a remediation; `last_affected` and `limit` close a segment
    WITHOUT naming one, and must not be reported as a fix.
    """
    kind = rng.get('type')
    if kind not in SEMVER_RANGE_TYPES:
        # GIT ranges hold commit hashes; comparing an npm version to them is undefined.
        notes.append({'range_type_not_comparable': kind})
        return None
    for segment in segments(rng.get('events') or []):
        start, end, terminator = segment
        # `last_affected` names the last version that IS affected, so the segment is
        # closed inclusively. `fixed` and `limit` name the first version that is not,
        # so they close it exclusively. Using `<` for all three put a version sitting
        # exactly on a `last_affected` boundary outside its own affected segment.
        closer = '<=' if terminator == 'last_affected' else '<'
        expression = f'>={start or "0.0.0"}' + (f' {closer}{end}' if end else '')
        verdict = semver.satisfies(installed, expression)
        if verdict is None:
            notes.append({'semver_undecidable': expression, 'version': installed})
            continue
        if not verdict:
            continue
        if terminator == 'fixed':
            return end
        # The install is inside an affected segment that names no fix.
        notes.append({'segment_without_fix': terminator, 'range': expression})
        return None
    return None


def segments(events):
    """[(introduced, terminator_version, terminator_kind), ...] in order."""
    out, start = [], None
    for event in events:
        if 'introduced' in event:
            if start is not None:
                out.append((start, None, 'open'))   # unterminated previous segment
            start = event['introduced']
            continue
        for kind in ('fixed', 'last_affected', 'limit'):
            if kind in event:
                out.append((start, event[kind], kind))
                start = None
                break
    if start is not None:
        out.append((start, None, 'open'))
    return out


class Semver:
    """npm's own semver, executed in the runner (protocol §5.4)."""

    def __init__(self, work):
        self.work = work
        self.cache = {}

    def _call(self, op, *args):
        key = (op, args)
        if key in self.cache:
            return self.cache[key]
        result = run(['node', str(SEMVER_HELPER), op, *args], self.work, timeout=60)
        value = as_json(result)
        answer = None if not value or value.get('error') else value.get('result')
        self.cache[key] = answer
        return answer

    def satisfies(self, version, expression):
        return self._call('satisfies', version, expression)

    def max_version(self, versions):
        return self._call('max', json.dumps(sorted(set(versions))))


# ------------------------------------------------------------------ endpoints

def install_gate(work, package, expected_version, store):
    """Protocol §5.2 - every step passes, or there is no primary endpoint at all."""
    out = {
        'lockfile_constructable': (work / 'package-lock.json').exists(),
        'install_pass_scripts_suppressed': False,
        'dependency_resolution_pass': False,
        'target_version_present': False,
        'runtime_compatibility_not_tested': True,
        'native_build_unverified_scripts_suppressed': False,
        'failure_reason': None,
    }
    if not out['lockfile_constructable']:
        out['failure_reason'] = 'lockfile_missing'
        return out
    install = run(['npm', 'ci', *NO_SCRIPTS, '--audit=false', '--fund=false'],
                  work, timeout=600)
    out['install_pass_scripts_suppressed'] = install['exit_code'] == 0
    if install['exit_code'] != 0:
        out['failure_reason'] = classify_failure(install)
        out['install_stderr'] = install['stderr']
        return out

    listed = run(['npm', 'ls', '--all', '--json'], work, timeout=300)
    out['npm_ls_sha256'] = store.keep_result('npm_ls', listed)
    out['npm_ls_exit_code'] = listed['exit_code']
    tree = as_json(listed)
    # npm ls exits non-zero on ELSPROBLEMS while STILL printing a full tree. Parsing
    # succeeded is not the same as the tree being sound (R37c-P0).
    problems = (tree or {}).get('problems') or []
    out['npm_ls_problems'] = problems[:10]
    out['dependency_resolution_pass'] = (listed['exit_code'] == 0 and tree is not None
                                         and not problems)
    if not out['dependency_resolution_pass']:
        out['failure_reason'] = ('dependency_tree_unreadable' if tree is None
                                 else 'dependency_tree_has_problems')
        return out

    found = (tree.get('dependencies') or {}).get(package) or {}
    out['resolved_version'] = found.get('version')
    out['declared_range'] = declared_range(work, package)
    out['target_version_present'] = found.get('version') == expected_version
    if not out['target_version_present']:
        out['failure_reason'] = 'target_version_absent_from_tree'
        return out
    if (work / 'node_modules' / package / 'binding.gyp').exists():
        # Scripts were suppressed, so nothing was built. Flag it; do not claim it works.
        out['native_build_unverified_scripts_suppressed'] = True
    return out


def gate_passed(gate):
    return all(gate.get(k) for k in ('lockfile_constructable',
                                     'install_pass_scripts_suppressed',
                                     'dependency_resolution_pass',
                                     'target_version_present'))


def classify_failure(result):
    blob = ((result.get('stderr') or '') + (result.get('stdout') or '')).lower()
    if 'eresolve' in blob or 'peer dep' in blob or 'conflicting peer' in blob:
        return 'peer_dependency'
    if 'etarget' in blob or 'no matching version' in blob or 'e404' in blob:
        return 'version_not_found'
    if 'econnreset' in blob or 'etimedout' in blob or 'enotfound' in blob:
        return 'registry_error'
    # The PUBLISHED manifest names a dependency npm cannot fetch at all - `link:`,
    # `file:`, `workspace:` survive publication and are only resolvable inside the
    # author's own tree. Both openlearnx environments in the R37e pre-check failed this
    # way and landed in `other`, which would have merged "this package cannot be
    # installed by anyone" with "we do not know what happened" (protocol paragraph 9,
    # no_silent_exclusion). It is a property of the package, not of our environment.
    if 'eunsupportedprotocol' in blob or 'unsupported url type' in blob:
        return 'unsupported_dependency_protocol'
    if 'could not resolve' in blob:
        return 'transitive_constraint'
    return 'other'


def detection(env, scans):
    """Per scanner, per query. A scanner that could not run reports no verdict at all."""
    out = {}
    status = {'npm_audit': scans['npm_audit'].get('status'),
              'osv_scanner': scans['osv_scanner'].get('status')}
    found = {
        'npm_audit': set(ids_from_npm_audit(scans['npm_audit'].get('parsed'))),
        'osv_scanner': set(ids_from_osv(scans['osv_scanner'].get('parsed'))),
    }
    # Cited by an advisory title but not claimed by any advisory. Recorded, never
    # matched against (R37f-P0).
    cited = set(textual_references_from_npm_audit(scans['npm_audit'].get('parsed')))
    for q in env['queries']:
        targets = set(q['target_advisory_identifiers'])
        cell = {'targets': sorted(targets)}
        for name in ('npm_audit', 'osv_scanner'):
            if status[name] != 'ok':
                # Not "found nothing" - could not be asked. Excluded downstream.
                cell[name] = {'status': status[name], 'matched': None}
            else:
                cell[name] = {'status': 'ok',
                              'matched': sorted(targets & found[name])}
        usable = [c for c in (cell['npm_audit'], cell['osv_scanner'])
                  if c['status'] == 'ok']
        cell['any_scanner'] = {
            'matched': sorted({m for c in usable for m in c['matched']}),
            'usable_scanners': len(usable),
            'note': 'display only - not a criterion (protocol 5.1)'}
        # A target that ONLY appears inside some advisory's prose. This is what a
        # follow-up "incomplete fix for X" advisory looks like: X itself is cleared and
        # a DIFFERENT advisory is present. Reported so the ingest can say that, rather
        # than being silently dropped.
        cell['textual_reference_only'] = sorted(targets & cited)
        out[q['entity_id']] = cell
    return {'per_query': out, 'scanner_status': status,
            'scanner_identifiers': {k: sorted(v) for k, v in found.items()},
            'npm_audit_textual_references': sorted(cited),
            'textual_references_note':
                'cited in an advisory TITLE, not claimed by any advisory; never matched'}


# ------------------------------------------------------------------ driver

def process(env, unified_versions, work, store):
    package, installed = env['package'], env['installed_version']
    semver = Semver(work)
    record = {'env_id': env['env_id'], 'package': package,
              'installed_version': installed,
              'queries': [q['entity_id'] for q in env['queries']],
              'phase1': None, 'phase2': {}, 'errors': []}

    built = lockfile_for(work, package, installed)
    if built['exit_code'] != 0 or built['pinned_exactly'] is not True:
        record['phase1'] = {
            'lockfile_constructable': built['exit_code'] == 0,
            'pinned_exactly': built['pinned_exactly'],
            'declared_range': built['declared_range'],
            'failure_reason': ('declared_range_not_exact' if built['exit_code'] == 0
                               else classify_failure(built)),
            'stderr': built['stderr']}
        record['errors'].append('baseline fixture could not be pinned')
        return record

    baseline = scan_both(work, store, 'baseline')
    record['phase1'] = {'lockfile_constructable': True, 'pinned_exactly': True,
                        'declared_range': built['declared_range'],
                        'scans': baseline, 'detection': detection(env, baseline)}

    targets = sorted({i for q in env['queries']
                      for i in q['target_advisory_identifiers']})
    recommendations = {
        ARM_NPM: npm_audit_recommendation(baseline, package, work, store),
        ARM_OSV: osv_recommendation(baseline, package, installed, targets, semver),
        # The Unified arm decides nothing here - it reads the frozen manifest.
        ARM_UNIFIED: {'versions': unified_versions,
                      'source': 'frozen H2_UNIFIED_RECOMMENDATIONS.json manifest'},
        ARM_NVD: {'version': None,
                  'source': 'no off-the-shelf NVD-only npm scanner exists'},
    }
    record['recommendations'] = recommendations
    # `npm audit fix` above mutated the tree; restore the baseline before phase 2.
    lockfile_for(work, package, installed)

    record['phase2'][ARM_NVD] = {'outcome': 'not_evaluated_no_operational_scanner',
                                 'excluded_from_operational_denominator': True}

    for arm in OPERATIONAL_ARMS:
        rec = recommendations[arm]
        if rec.get('unusable'):
            record['phase2'][arm] = {'outcome': 'scanner_unusable',
                                     'reason': rec['unusable'],
                                     'excluded_from_operational_denominator': True}
            continue
        # npm's `fixAvailable: true` remediation is a whole lockfile, not a version
        # (R37f-P0). Everything else names a version for the top-level package.
        if rec.get('lockfile'):
            record['phase2'][arm] = {'outcome': 'attempted', 'attempts': [
                attempt(work, store, env, package, rec.get('version'),
                        lockfile=rec['lockfile'], manifest=rec.get('manifest'),
                        lockfile_sha256=rec.get('lockfile_sha256'))]}
            continue
        versions = rec.get('versions') or ([rec['version']] if rec.get('version')
                                           else [])
        if not versions:
            record['phase2'][arm] = {'outcome': 'no_action_generated',
                                     'tool_says_no_fix': rec.get('tool_says_no_fix'),
                                     'audit_fix_changed_nothing':
                                         rec.get('audit_fix_changed_nothing'),
                                     'unresolved': rec.get('unresolved')}
            continue
        record['phase2'][arm] = {'outcome': 'attempted', 'attempts': [
            attempt(work, store, env, package, fix) for fix in versions]}
    return record


def restore_fixed_tree(work, lockfile, manifest):
    """Put back verbatim what `npm audit fix` wrote - both files, nothing re-resolved.

    npm defines audit fix as remediation over the whole dependency tree, so the tree it
    wrote IS the recommendation. Re-running `npm install` here would let npm resolve it
    again and could substitute a different tree; `npm ci` in the install gate installs
    exactly this lockfile, and fails loudly if the two files disagree (R37f-P0).
    """
    clean(work)
    if manifest is not None:
        (work / 'package.json').write_text(manifest, encoding='utf-8')
    (work / 'package-lock.json').write_text(lockfile, encoding='utf-8')


def attempt(work, store, env, package, fix, lockfile=None, manifest=None,
            lockfile_sha256=None):
    """Install first. Re-scan only if the install gate passes (protocol §5.2)."""
    kind = 'lockfile' if lockfile is not None else 'version'
    if lockfile is not None:
        restore_fixed_tree(work, lockfile, manifest)
    else:
        built = lockfile_for(work, package, fix)
        if built['exit_code'] != 0 or built['pinned_exactly'] is not True:
            return {'recommended_version': fix, 'remediation_kind': kind,
                    'outcome': 'remediation_not_installable',
                    'install_gate': {'lockfile_constructable': built['exit_code'] == 0,
                                     'pinned_exactly': built['pinned_exactly'],
                                     'failure_reason': classify_failure(built)},
                    'stderr': built['stderr']}
    gate = install_gate(work, package, fix, store)
    if lockfile is not None:
        # `target_version_present` still means what it says: `npm ci` installs this
        # lockfile, so the top-level package must resolve to the version npm's own fix
        # put there. It is NOT overridden - an unevaluated step may not report a pass.
        gate['remediation_lockfile_sha256'] = lockfile_sha256
        gate['remediation_lockfile_sha256_on_disk'] = sha256(read_lockfile(work))
    if not gate_passed(gate):
        # No re-scan, and therefore no primary-endpoint result. A fix that cannot be
        # installed must never be recorded as remediated.
        return {'recommended_version': fix,
                'remediation_kind': 'lockfile' if lockfile is not None else 'version',
                'outcome': 'remediation_not_installable', 'install_gate': gate}
    rescan = scan_both(work, store, 'rescan')
    # NOT "remediated": the re-scan has run but nothing here has read it, and a scanner
    # may have failed outright. Whether the target actually cleared is the ingest's
    # judgement, per scanner (R37d-P1). The runner reports what it did, not what it
    # achieved.
    return {'recommended_version': fix,
            'remediation_kind': 'lockfile' if lockfile is not None else 'version',
            'outcome': 'installed_and_rescanned',
            'install_gate': gate, 'scans': rescan,
            'detection_after': detection(env, rescan)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--spec', required=True)
    ap.add_argument('--unified', required=True,
                    help='H2_UNIFIED_RECOMMENDATIONS.json - the ONLY Unified source')
    ap.add_argument('--shard', type=int, required=True)
    ap.add_argument('--shard-count', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--raw-out', required=True)
    ap.add_argument('--limit', type=int, default=0,
                    help='pre-check only: stop after N environments')
    args = ap.parse_args()

    spec = json.loads(Path(args.spec).read_text(encoding='utf-8'))
    manifest = json.loads(Path(args.unified).read_text(encoding='utf-8'))
    unified = {e['env_id']: [r['version'] for r in e['recommendations']]
               for e in manifest['environments']}

    mine = [e for i, e in enumerate(spec['environments'])
            if i % args.shard_count == args.shard]
    if args.limit:
        mine = mine[:args.limit]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    store = RawStore(args.raw_out)
    print(f'shard {args.shard}/{args.shard_count}: {len(mine)} environments')

    with out.open('w', encoding='utf-8') as handle:
        for n, env in enumerate(mine, 1):
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    record = process(env, unified.get(env['env_id'], []),
                                     Path(tmp), store)
                except Exception as exc:               # noqa: BLE001 - must not abort
                    # An environment that blew up still gets a line. Silence here would
                    # be indistinguishable from "never attempted" (protocol §9).
                    record = {'env_id': env['env_id'], 'package': env['package'],
                              'installed_version': env['installed_version'],
                              'errors': [f'{type(exc).__name__}: {exc}'],
                              'phase1': None, 'phase2': {}}
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + '\n')
            handle.flush()
            if n % 10 == 0:
                print(f'  {n}/{len(mine)}', flush=True)
    store.close()
    print(f'wrote {out} and {args.raw_out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
