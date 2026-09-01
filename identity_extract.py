#!/usr/bin/env python3
"""Pure extraction helpers shared by the identity layer - NO module-level side effects.

Lifted verbatim out of build_unified_model.py so that importing the extractors cannot
touch the filesystem: the v1 builder runs `OUT.mkdir()` at import time, and the
acceptance gate needs to install its I/O spy BEFORE importing anything it audits.

build_unified_model.py deliberately keeps its own copies. Its build is a frozen,
rejected artefact; editing the source that produced it would break the correspondence
between artefact and code that the rest of this project relies on. The duplication is
the honest trade, and v1 is never re-run.

Every function here reads only the dict handed to it. Nothing in this module knows what
an entity is, and nothing here resolves identity.
"""
import gzip
import hashlib
import json
import re
import unicodedata

CVE_RE = re.compile(r'^CVE-\d{4}-\d+$')
GHSA_RE = re.compile(r'^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$', re.I)
CWE_RE = re.compile(r'^CWE-\d+$')
SENTINEL_CWE_RE = re.compile(r'^NVD-CWE-', re.I)


# ---------------------------------------------------------------- transform registry
# class is a PER-OBSERVATION property. It is deliberately not the H1 schema-diff
# taxonomy, which classifies pairwise schema availability between two formats.
TRANSFORM_RULES = [
    ('id.copy', 'identity_copy', 'identifier copied verbatim', True, ['nvd', 'ghsa', 'osv']),
    ('cwe.copy', 'identity_copy', 'CWE id copied verbatim', True, ['nvd', 'ghsa', 'osv']),
    ('cwe.sentinel', 'identity_copy',
     'NVD sentinel weakness (NVD-CWE-noinfo / NVD-CWE-Other) kept as an explicit '
     '"no usable weakness" statement instead of being filtered out', True, ['nvd']),
    ('severity.cvss_vector', 'identity_copy', 'CVSS vector string copied verbatim', True,
     ['nvd', 'ghsa', 'osv']),
    ('severity.scale_label', 'lossless_normalization',
     'CVSS metric block name mapped to a scale enum', True, ['nvd', 'ghsa', 'osv']),
    ('severity.placeholder', 'excluded',
     'source emitted the key but no value (GHSA {vector_string: null, score: 0.0}); '
     'recorded as placeholder, never as a score of 0.0', False, ['ghsa']),
    ('severity.ssvc', 'source_extension',
     'NVD SSVC decision block retained as a source extension', True, ['nvd']),
    ('range.osv_events', 'lossless_normalization',
     'OSV range events (introduced / fixed / last_affected) kept as an ordered event '
     'list with their range type', True, ['osv']),
    ('range.nvd_bounds', 'lossless_normalization',
     'NVD cpeMatch version bounds kept as four explicit inclusive/exclusive bounds '
     'rather than being flattened into a display string', True, ['nvd']),
    ('range.ghsa_text', 'lossy_projection',
     'GHSA vulnerable_version_range is free text; the original expression is kept '
     'verbatim but no comparator is imposed', False, ['ghsa']),
    ('remediation.ghsa_first_patched', 'identity_copy',
     'GHSA first_patched_version is a stated remediation', True, ['ghsa']),
    ('remediation.osv_fixed_event', 'lossless_normalization',
     'OSV fixed event is a stated remediation', True, ['osv']),
    ('remediation.nvd_proxy', 'derived_proxy',
     'NVD publishes no remediation field (0% availability). An exclusive upper bound '
     'is a PROXY for a fix and is labelled as one, never as a stated fix', False, ['nvd']),
    ('package.copy', 'identity_copy', 'package name / ecosystem / purl copied', True,
     ['ghsa', 'osv']),
    ('package.cpe_split', 'lossy_projection',
     'CPE 2.3 criteria split into vendor:product; the full CPE string is retained '
     'as cpe so the remaining components are not lost', False, ['nvd']),
    ('text.copy', 'identity_copy', 'title / reference / note copied verbatim', True,
     ['nvd', 'ghsa', 'osv']),
]


# R12-F3: bumped from -nfc-1 when NFC actually started being applied in round 11.
# One version name must not describe two behaviours: -nfc-1 named the step but never
# performed it, so 11 records in the frozen corpus hashed differently under the two.
CANONICALIZATION = 'json-sorted-keys-nfc-2'
CANONICALIZATION_LEGACY = 'json-sorted-keys-nfc-1'   # v1 + rounds <=10: NFC never applied


def nfc(s):
    """Unicode NFC. The canonicalization algorithm is NAMED for this step (R11-F5).

    Until round 11 the name promised NFC and no code performed it, so two byte
    sequences meaning the same text hashed differently. 11 string values in the frozen
    corpus are not NFC-normalised, spread over 11 records; without this, a future
    temporal diff would report those as content changes when nothing changed.
    """
    return unicodedata.normalize('NFC', s) if isinstance(s, str) else s


def nfc_deep(o):
    """NFC every string in a JSON-shaped structure, keys included."""
    if isinstance(o, str):
        return unicodedata.normalize('NFC', o)
    if isinstance(o, dict):
        return {unicodedata.normalize('NFC', k) if isinstance(k, str) else k: nfc_deep(v)
                for k, v in o.items()}
    if isinstance(o, list):
        return [nfc_deep(v) for v in o]
    return o


def sha256_str(s):
    return hashlib.sha256(nfc(s).encode('utf-8')).hexdigest()


def sha256_obj(o):
    return sha256_str(json.dumps(nfc_deep(o), sort_keys=True, ensure_ascii=False,
                                 separators=(',', ':')))


def entity_id_for(anchor):
    """Persistent id derived from the ANCHOR, not from component membership.

    A component fingerprint changes whenever membership changes, so it can only ever be
    a snapshot identifier. Anchoring on a source-issued identifier makes the id
    deterministic for a given member set - NOT stable across snapshots, which would
    need a persisted anchor registry this build does not have.
    """
    return 'UVM-' + sha256_str(anchor)[:16]


def iter_jsonl_gz(path):
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl_gz(path, rows):
    tmp = path.with_suffix(path.suffix + '.partial')
    with gzip.GzipFile(filename='', mode='wb', fileobj=open(tmp, 'wb'), mtime=0) as gz:
        for r in rows:
            gz.write((json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n').encode('utf-8'))
    tmp.replace(path)
    return path


def consume(out, rule, *paths):
    """Record the exact SOURCE LEAF PATHS this rule consumed.

    Retention is measured against every non-empty leaf in the source document, so
    coverage has to be stated leaf-precisely. A json_pointer aimed at a container
    would either under-credit (matching no leaf) or over-credit (claiming siblings
    the extractor never read).
    """
    for p in paths:
        if p:
            out['consumed'].append({'path': p, 'rule': rule})


def obs(source, ref, native_id, pointer, raw_sha, original, status, rule, observed_at):
    return {'source': source, 'source_record_ref': ref, 'native_id': native_id,
            'json_pointer': pointer, 'raw_record_sha256': raw_sha,
            'original_value': original, 'value_status': status,
            'transform_rule': rule, 'observed_at': observed_at}


# ---------------------------------------------------------------- source extractors
def extract_nvd(raw):
    """NVD. Captures EVERY metric block: the old pilot looped only over
    (V31, V30, V2) and never even looked at cvssMetricV40 (3,215 records) or
    ssvcV203 (8,853). 8,867 records carry more than one metric entry."""
    cve = raw.get('cve') or {}
    out = {'native_id': cve.get('id'), 'cves': [], 'severities': [], 'cwes': [],
           'affected': [], 'texts': [], 'warnings': [], 'consumed': [],
           'published': cve.get('published'), 'modified': cve.get('lastModified')}
    if cve.get('id'):
        out['cves'].append(cve['id'])
    consume(out, 'id.copy', 'cve.id')

    scale_of = {'cvssMetricV2': 'CVSS_V2', 'cvssMetricV30': 'CVSS_V3_0',
                'cvssMetricV31': 'CVSS_V3_1', 'cvssMetricV40': 'CVSS_V4_0'}
    for key, arr in (cve.get('metrics') or {}).items():
        for i, m in enumerate(arr or []):
            ptr = f'/cve/metrics/{key}/{i}'
            if key.startswith('ssvc'):
                out['severities'].append({'scale': 'SSVC', 'score': None,
                                          'vector': None, 'label': None,
                                          'pointer': ptr, 'original': m,
                                          'status': 'provided', 'rule': 'severity.ssvc'})
                consume(out, 'severity.ssvc', f'cve.metrics.{key}[]')
                continue
            c = m.get('cvssData') or {}
            out['severities'].append({
                'scale': scale_of.get(key, 'OTHER'), 'score': c.get('baseScore'),
                'vector': c.get('vectorString'), 'label': c.get('baseSeverity'),
                'pointer': ptr + '/cvssData', 'original': c.get('vectorString'),
                'status': 'provided' if c.get('vectorString') else 'source_not_provided',
                'rule': 'severity.cvss_vector'})
            consume(out, 'severity.cvss_vector',
                    f'cve.metrics.{key}[].cvssData.vectorString',
                    f'cve.metrics.{key}[].cvssData.baseScore',
                    f'cve.metrics.{key}[].cvssData.baseSeverity')

    for wi, w in enumerate(cve.get('weaknesses') or []):
        for di, d in enumerate(w.get('description') or []):
            v = (d.get('value') or '').strip()
            if not v:
                continue
            sentinel = bool(SENTINEL_CWE_RE.match(v))
            if not (CWE_RE.match(v) or sentinel):
                continue
            out['cwes'].append({'value': v, 'is_sentinel': sentinel,
                                'pointer': f'/cve/weaknesses/{wi}/description/{di}/value',
                                'original': v, 'status': 'provided',
                                'rule': 'cwe.sentinel' if sentinel else 'cwe.copy'})
            consume(out, 'cwe.sentinel' if sentinel else 'cwe.copy',
                    'cve.weaknesses[].description[].value')

    for ci, cfg in enumerate(cve.get('configurations') or []):
        for ni, node in enumerate(cfg.get('nodes') or []):
            for mi, m in enumerate(node.get('cpeMatch') or []):
                crit = m.get('criteria') or ''
                parts = crit.split(':')
                vendor = parts[3] if len(parts) > 3 else ''
                product = parts[4] if len(parts) > 4 else ''
                bounds = {'start_including': m.get('versionStartIncluding'),
                          'start_excluding': m.get('versionStartExcluding'),
                          'end_including': m.get('versionEndIncluding'),
                          'end_excluding': m.get('versionEndExcluding')}
                # NVD has no remediation field; an exclusive upper bound is a PROXY
                proxy = m.get('versionEndExcluding')
                out['affected'].append({
                    'package_name': f'{vendor}:{product}' if vendor and product else (crit or None),
                    'ecosystem': 'cpe', 'purl': None, 'cpe': crit or None,
                    'ranges': [{'range_kind': 'bounds', 'range_type': 'CPE',
                                'bounds': bounds, 'comparator': 'cpe',
                                'original_expression': crit or None}],
                    'first_patched_version': None,
                    'remediation_kind': 'derived_proxy' if proxy else 'none',
                    'proxy_derived_from': 'versionEndExcluding' if proxy else None,
                    'pointer': f'/cve/configurations/{ci}/nodes/{ni}/cpeMatch/{mi}',
                    'original': crit, 'status': 'provided',
                    'rule': 'remediation.nvd_proxy' if proxy else 'range.nvd_bounds'})
                consume(out, 'remediation.nvd_proxy' if proxy else 'range.nvd_bounds',
                        'cve.configurations[].nodes[].cpeMatch[].criteria',
                        'cve.configurations[].nodes[].cpeMatch[].versionStartIncluding',
                        'cve.configurations[].nodes[].cpeMatch[].versionStartExcluding',
                        'cve.configurations[].nodes[].cpeMatch[].versionEndIncluding',
                        'cve.configurations[].nodes[].cpeMatch[].versionEndExcluding')

    for di, d in enumerate(cve.get('descriptions') or []):
        if d.get('lang') == 'en' and d.get('value'):
            out['texts'].append({'field': 'notes', 'value': d['value'],
                                 'pointer': f'/cve/descriptions/{di}/value',
                                 'original': d['value'], 'status': 'provided',
                                 'rule': 'text.copy'})
            consume(out, 'text.copy', 'cve.descriptions[].value')
    return out


def extract_ghsa(raw):
    """GHSA. cvss_severities always carries BOTH cvss_v3 and cvss_v4 keys
    (9,477/9,477) but only 1,348 populate both. An unpopulated block reads
    {vector_string: null, score: 0.0} - recorded as a placeholder, never 0.0."""
    out = {'native_id': raw.get('ghsa_id'), 'cves': [], 'severities': [], 'cwes': [],
           'affected': [], 'texts': [], 'warnings': [], 'consumed': [],
           'published': raw.get('published_at'), 'modified': raw.get('updated_at')}
    if raw.get('cve_id'):
        out['cves'].append(raw['cve_id'])
    consume(out, 'id.copy', 'ghsa_id', 'cve_id', 'identifiers[].value', 'identifiers[].type')
    for i, ident in enumerate(raw.get('identifiers') or []):
        v = ident.get('value')
        if v and CVE_RE.match(v) and v not in out['cves']:
            out['cves'].append(v)

    for key, scale in (('cvss_v3', 'CVSS_V3_1'), ('cvss_v4', 'CVSS_V4_0')):
        blk = (raw.get('cvss_severities') or {}).get(key)
        if blk is None:
            continue
        vec = blk.get('vector_string')
        if vec:
            out['severities'].append({'scale': scale, 'score': blk.get('score'),
                                      'vector': vec, 'label': raw.get('severity'),
                                      'pointer': f'/cvss_severities/{key}',
                                      'original': vec, 'status': 'provided',
                                      'rule': 'severity.cvss_vector'})
            consume(out, 'severity.cvss_vector',
                    f'cvss_severities.{key}.vector_string',
                    f'cvss_severities.{key}.score', 'severity')
        else:
            # key present, value absent -> placeholder. score 0.0 is NOT a severity.
            out['severities'].append({'scale': scale, 'score': None, 'vector': None,
                                      'label': None,
                                      'pointer': f'/cvss_severities/{key}',
                                      'original': blk, 'status': 'placeholder',
                                      'rule': 'severity.placeholder'})
            consume(out, 'severity.placeholder',
                    f'cvss_severities.{key}.vector_string',
                    f'cvss_severities.{key}.score')

    for i, c in enumerate(raw.get('cwes') or []):
        v = (c.get('cwe_id') or '').strip() if isinstance(c, dict) else str(c).strip()
        if not v:
            continue
        out['cwes'].append({'value': v, 'is_sentinel': bool(SENTINEL_CWE_RE.match(v)),
                            'pointer': f'/cwes/{i}/cwe_id', 'original': v,
                            'status': 'provided', 'rule': 'cwe.copy'})
        consume(out, 'cwe.copy', 'cwes[].cwe_id', 'cwes[].name')

    for i, v in enumerate(raw.get('vulnerabilities') or []):
        pkg = v.get('package') or {}
        rng = v.get('vulnerable_version_range')
        fpv = v.get('first_patched_version')
        if isinstance(fpv, dict):
            fpv = fpv.get('identifier')
        out['affected'].append({
            'package_name': pkg.get('name'), 'ecosystem': pkg.get('ecosystem'),
            'purl': None, 'cpe': None,
            'ranges': [{'range_kind': 'text', 'range_type': 'TEXT', 'bounds': None,
                        'comparator': None, 'original_expression': rng}] if rng else [],
            'first_patched_version': fpv,
            'remediation_kind': 'stated_remediation' if fpv else 'none',
            'proxy_derived_from': None,
            'pointer': f'/vulnerabilities/{i}', 'original': rng,
            'status': 'provided' if rng else 'source_not_provided',
            'rule': 'remediation.ghsa_first_patched' if fpv else 'range.ghsa_text'})
        consume(out, 'package.copy', 'vulnerabilities[].package.name',
                'vulnerabilities[].package.ecosystem')
        consume(out, 'range.ghsa_text', 'vulnerabilities[].vulnerable_version_range')
        if fpv:
            consume(out, 'remediation.ghsa_first_patched',
                    'vulnerabilities[].first_patched_version',
                    'vulnerabilities[].first_patched_version.identifier')

    if raw.get('summary'):
        out['texts'].append({'field': 'title', 'value': raw['summary'],
                             'pointer': '/summary', 'original': raw['summary'],
                             'status': 'provided', 'rule': 'text.copy'})
        consume(out, 'text.copy', 'summary')
    consume(out, 'text.copy', 'description', 'published_at', 'updated_at')
    return out


def extract_osv(raw):
    """OSV. CVE identity comes from the NATIVE id as well as aliases: 1,145 sampled
    records have a CVE as their own id and 1,144 of those list no CVE in aliases, so
    an aliases-only lookup loses every one of them. `upstream` is NOT identity."""
    out = {'native_id': raw.get('id'), 'cves': [], 'severities': [], 'cwes': [],
           'affected': [], 'texts': [], 'warnings': [], 'consumed': [],
           'published': raw.get('published'), 'modified': raw.get('modified')}
    nid = raw.get('id') or ''
    if CVE_RE.match(nid):
        out['cves'].append(nid)
    for a in raw.get('aliases') or []:
        if CVE_RE.match(a) and a not in out['cves']:
            out['cves'].append(a)

    consume(out, 'id.copy', 'id', 'aliases[]')
    for i, s in enumerate(raw.get('severity') or []):
        # NB: OSV names this field `score` but it carries a VECTOR STRING.
        val = s.get('score')
        typ = (s.get('type') or '').upper()
        scale = {'CVSS_V2': 'CVSS_V2', 'CVSS_V3': 'CVSS_V3_1',
                 'CVSS_V4': 'CVSS_V4_0'}.get(typ, 'OTHER')
        out['severities'].append({'scale': scale, 'score': None,
                                  'vector': val if isinstance(val, str) else None,
                                  'label': None, 'pointer': f'/severity/{i}/score',
                                  'original': val,
                                  'status': 'provided' if val else 'source_not_provided',
                                  'rule': 'severity.cvss_vector'})
        consume(out, 'severity.cvss_vector', 'severity[].score', 'severity[].type')

    dbs = raw.get('database_specific') or {}
    for i, v in enumerate(dbs.get('cwe_ids') or []):
        if v:
            out['cwes'].append({'value': v, 'is_sentinel': bool(SENTINEL_CWE_RE.match(v)),
                                'pointer': f'/database_specific/cwe_ids/{i}',
                                'original': v, 'status': 'provided', 'rule': 'cwe.copy'})
            consume(out, 'cwe.copy', 'database_specific.cwe_ids[]')

    for ai, a in enumerate(raw.get('affected') or []):
        pkg = a.get('package') or {}
        ranges, fixed = [], None
        for ri, rg in enumerate(a.get('ranges') or []):
            events = []
            for e in rg.get('events') or []:
                for kind in ('introduced', 'fixed', 'last_affected', 'limit'):
                    if kind in e:
                        events.append({'kind': kind, 'value': e[kind]})
                        if kind == 'fixed' and not fixed:
                            fixed = e[kind]
            ranges.append({'range_kind': 'event_list',
                           'range_type': (rg.get('type') or 'UNKNOWN').upper(),
                           'events': events, 'comparator': (rg.get('type') or '').lower() or None,
                           'original_expression': None})
        out['affected'].append({
            'package_name': pkg.get('name'), 'ecosystem': pkg.get('ecosystem'),
            'purl': pkg.get('purl'), 'cpe': None, 'ranges': ranges,
            'first_patched_version': fixed,
            'remediation_kind': 'stated_remediation' if fixed else 'none',
            'proxy_derived_from': None,
            'pointer': f'/affected/{ai}', 'original': None,
            'status': 'provided', 'rule': 'remediation.osv_fixed_event' if fixed
            else 'range.osv_events'})
        consume(out, 'package.copy', 'affected[].package.name',
                'affected[].package.ecosystem', 'affected[].package.purl')
        consume(out, 'range.osv_events', 'affected[].ranges[].type',
                'affected[].ranges[].events[].introduced',
                'affected[].ranges[].events[].fixed',
                'affected[].ranges[].events[].last_affected')
        if fixed:
            consume(out, 'remediation.osv_fixed_event',
                    'affected[].ranges[].events[].fixed')

    if raw.get('summary'):
        out['texts'].append({'field': 'title', 'value': raw['summary'],
                             'pointer': '/summary', 'original': raw['summary'],
                             'status': 'provided', 'rule': 'text.copy'})
        consume(out, 'text.copy', 'summary')
    consume(out, 'text.copy', 'details', 'published', 'modified')
    return out

EXTRACTORS = {'nvd': extract_nvd, 'ghsa': extract_ghsa, 'osv': extract_osv}
