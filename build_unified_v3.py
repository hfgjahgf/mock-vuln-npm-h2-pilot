"""unified_model_v3 - CVE-keyed identity, with relations kept for traceability.

THE RULE, IN ONE LINE

  A CVE id is a national ID number. Two records merge only when that number is the
  same. "Referred from another hospital" (upstream) and "related to another case"
  (related) are relationships, not proof of being the same person. A record with no
  ID number is filed on its own.

  Supervisor ruling, frozen here as `identity_contract` in dataset_metadata:

  1. H1 = the frozen-window NVD/GHSA/OSV cross-ecosystem cohort of three PEER
     sources - near-balanced, not equal-weight: 10,000 NVD, 9,477 GHSA (the whole
     window census), 10,000 OSV = 29,477. H2 is scoped to npm/Node.js CI/CD.
  2. Same normalised CVE id -> same entity. Different CVE ids -> different entities,
     even inside one advisory.
  3. A multi-CVE advisory is ONE source record linked to SEVERAL CVE entities. Those
     CVEs are never merged with each other.
  4. A record with no CVE is kept independently, keyed `source::native_id`. No
     cross-source inference.
  5. alias / upstream / related are relations and provenance, NEVER identity edges.
  6. The full index is for back-query only. It never enters an analysis denominator;
     the 29,477 frozen records remain the H1 body.
  7. Severity: keep every original score. Where one derived value is needed, take the
     maximum - the worst case.

WHAT THIS REPLACES, AND WHAT IT DOES NOT TOUCH

  v2 (2.3.0-identity) stays exactly where it is: union-find over "verified 1:1"
  claims, policy D, ambiguity withholding. It is NOT overwritten and NOT modified -
  it remains as engineering history and as a supplementary sensitivity arm, and the
  R24b arm-1 gate still pins its reproduction. That gate also hashes
  build_identity_v2.py and identity_extract.py, so this module importing them is
  safe by construction: editing either would fail arm 1 immediately.

WHERE THE CVEs COME FROM

  `identity_extract.extract_{nvd,ghsa,osv}` already collect exactly the fields the
  ruling names - NVD's native id, GHSA's cve_id and identifiers[].value, OSV's native
  id and aliases - and `extract_osv`'s own docstring records that upstream is not
  identity. They are reused rather than re-typed: a second CVE extractor would be a
  second policy, and the difference between them would get called a finding.

  Cross-checked against a different code path (build_identity_v2.identity_candidates)
  before this module was written: both yield the same 17,695 CVEs, with zero
  normalisation events.

  python build_unified_v3.py                 # -> output/unified_model_v3/
  python build_unified_v3.py --out-dir DIR   # build elsewhere (determinism checks)
"""
import argparse
import hashlib
import json
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from build_identity_v2 import SOURCES, identity_candidates
from identity_extract import (CVE_RE, entity_id_for, extract_ghsa, extract_nvd,
                              extract_osv, iter_jsonl_gz, sha256_obj, sha256_str,
                              write_jsonl_gz)

ROOT = Path(__file__).resolve().parent
DEFAULT_IN = ROOT / 'output' / 'h1_discovery'
DEFAULT_OUT = ROOT / 'output' / 'unified_model_v3'
MODEL_VERSION = '3.3.0-cve-keyed'
EXTRACTORS = {'nvd': extract_nvd, 'ghsa': extract_ghsa, 'osv': extract_osv}

# R28: the pre-registered sensitivity arms need the SAME builder with one mapping
# changed, not a second builder. Defaults are the primary model, and a gate asserts the
# primary build still reproduces byte for byte with these present - a switch is only
# safe if leaving it alone provably changes nothing.
MAPPING_SWITCHES = {
    'nvd_kev_texts': True,          # cisaVulnerabilityName -> summary_text
    'nvd_stated_boundary': True,    # changes[].at -> fixed_version
    'osv_custom_fixed': False,      # ecosystem/database_specific -> fixed_version
}


def switches(**overrides):
    """The switch set for one arm, defaults filled in and unknown names rejected."""
    unknown = set(overrides) - set(MAPPING_SWITCHES)
    if unknown:
        raise ValueError(f'unknown mapping switch: {sorted(unknown)}')
    return {**MAPPING_SWITCHES, **overrides}


SECTIONS = ('entities', 'source_records', 'entity_record_links', 'relations',
            'assertions_severity', 'assertions_cwe', 'assertions_affected',
            'assertions_generic', 'coverage_map', 'completeness_matrix',
            'completeness_matrix_no_cve')

IDENTITY_CONTRACT = [
    'H1 = frozen-window NVD/GHSA/OSV cohort of three PEER sources, near-balanced '
    'rather than equal-weight (nvd 10,000 / ghsa 9,477 / osv 10,000 = 29,477); H2 '
    'is scoped to npm/Node.js CI/CD',
    'same normalised CVE id -> same entity',
    'different CVE ids -> different entities, even within one advisory',
    'a multi-CVE advisory is one source record linked to several CVE entities; those '
    'CVEs are not merged',
    'a record with no DIRECT CVE identity is kept independently as '
    'native:<source>:<native_id>, with no cross-source inference. "No direct CVE '
    'identity" rather than "no CVE": 7,810 of the 9,528 name a CVE in upstream or '
    'related, and only 1,718 carry no CVE information anywhere. Per the OSV schema '
    '(ossf.github.io/osv-schema) aliases means the same vulnerability, upstream '
    'means an upstream vulnerability, and related means merely related - so a CVE '
    'in upstream/related is context, not this record\'s identity',
    'alias / upstream / related are relations and provenance, never identity edges',
    'the full index is back-query only and never enters an analysis denominator',
    'severity: every original score is kept; a single derived value is the maximum '
    '(worst case), taken WITHIN a scale because CVSS versions are not comparable',
]


ASSERTION_CONTRACT = [
    'three layers: the advisory is stored ONCE (source_records); each CVE is its own '
    'entity; every assertion is placed by evidence (assertion layer)',
    'assertion_scope is one of entity_specific / shared_explicit / record_level',
    'attribution_status is one of attributed / ambiguous / not_vulnerability_scoped',
    'counts_toward_completeness is derived: scope in {entity_specific, '
    'shared_explicit}. H1 completeness and H2 read ONLY that flag',
    'a multi-CVE advisory links several entities, but a single score or CWE it '
    'carries is ambiguous and stays at advisory level - copying it to each CVE would '
    'turn one statement into several complete-looking records',
    'shared_explicit is the ONLY class that may appear against several entities, and '
    'it must carry attribution_evidence; no structured field in these sources '
    'expresses it, so in this corpus it is 0',
    'advisory-level metadata (published, modified, references) is not an assertion at '
    'all - it lives on the record and can never reach an entity',
    'a CVE mentioned only in prose is never identity: CVEs come from declared '
    'identity fields only',
    'no-direct-CVE-identity records are normalised, retrievable and H2-eligible on '
    'the same terms; they are reported as their own stratum because they cannot join '
    'CVE-keyed cross-source pairing, not because they are worth less',
    'an assertion COUNTS toward completeness only when it is attributable AND '
    'carries a usable value: a placeholder severity, a sentinel CWE and an affected '
    'row with no fixed version are rows, not values',
    'a source that the back-query says holds a CVE, but whose record content this '
    'snapshot never collected, is content_not_observed - its field booleans are '
    'null, never false, because nothing was observed and so nothing is missing',
]


def norm(v):
    """trim + NFC, the normalisation the ruling's "normalised CVE id" names.

    Measured on this cohort: it changes nothing (0 events), which is reported rather
    than assumed - `CVE_RE` is anchored, so a stray trailing space would silently
    turn one CVE into a no-CVE record without it.
    """
    return unicodedata.normalize('NFC', v.strip()) if isinstance(v, str) else v


def normalised_cves(values):
    out, seen = [], set()
    for v in values or []:
        n = norm(v)
        if n and CVE_RE.match(n) and n not in seen:
            seen.add(n)
            out.append(n)
    return sorted(out)


def cve_bases(src, raw):
    """Which declared FIELD each CVE came from, for link provenance.

    `identity_candidates` already labels every declared identifier with its basis
    (`nvd_cve_id`, `ghsa_cve_id`, `ghsa_identifiers`, `osv_id`, `osv_aliases`), so
    the link rows can say where the number was read from instead of asserting it.
    """
    bases = defaultdict(set)
    _, cands = identity_candidates(src, raw)
    for c in cands:
        cid = norm(c.get('id'))
        if cid and CVE_RE.match(cid):
            bases[cid].add(c['basis'])
    return {k: sorted(v) for k, v in bases.items()}


def declared_relations(src, raw, cve_set):
    """alias / upstream / related - kept whole, for traceability, never for merging.

    Every alias assertion is recorded, CVE-shaped ones included, flagged
    `also_identity_link` so the relation table is a complete account of what the
    record said rather than the leftovers after identity took its share.
    """
    rows = []
    _, cands = identity_candidates(src, raw)
    for c in cands:
        cid = norm(c.get('id'))
        if not cid or c['edge_type'] == 'native_id':
            continue
        rows.append({'relation_type': 'alias', 'target': cid, 'field': c['basis'],
                     'target_is_cve_shaped': bool(CVE_RE.match(cid)),
                     'also_identity_link': cid in cve_set})
    if src == 'osv':
        for field in ('upstream', 'related'):
            for v in raw.get(field) or []:
                t = norm(v) if isinstance(v, str) else None
                if not t:
                    continue
                rows.append({
                    'relation_type': field, 'target': t, 'field': f'osv_{field}',
                    'target_is_cve_shaped': bool(CVE_RE.match(t)),
                    # rule 5: a CVE named in upstream/related is STILL only a
                    # relation. This flag is what makes that visible instead of
                    # implicit - and what the sensitivity block counts.
                    'also_identity_link': False})
    return rows


def derived_severity(severities):
    """One value per scale: the maximum numeric score. Worst case, per the ruling.

    Three ways this goes silently wrong, so all three are handled and counted:
      - CVSS_V2 / V3_0 / V3_1 / V4_0 are NOT comparable, so the max is per scale and
        never across them.
      - GHSA writes {vector_string: null, score: 0.0} for a block it did not
        populate; `extract_ghsa` already records that as score=None, and 0.0 must
        never be read as a score of zero.
      - OSV's `severity[].score` holds a VECTOR STRING, not a number; `extract_osv`
        records score=None and keeps the vector. Vectors are retained but cannot be
        maxed without parsing, so they are excluded and counted.
    """
    by_scale = defaultdict(list)
    skipped = Counter()
    for s in severities:
        score = s.get('score')
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            by_scale[s.get('scale') or 'OTHER'].append(float(score))
        elif s.get('vector'):
            skipped['vector_only_no_numeric_score'] += 1
        else:
            skipped['placeholder_or_absent'] += 1
    return ({k: max(v) for k, v in sorted(by_scale.items())}, dict(sorted(
        skipped.items())))


ASSERTION_SCOPES = ('entity_specific', 'shared_explicit', 'record_level')
ATTRIBUTION_STATUSES = ('attributed', 'ambiguous', 'not_vulnerability_scoped')
NARRATIVE_KINDS = ('text', 'warning')


def classify_assertion(kind, entity_ids, native_cve_entity_id):
    """THE assertion-layer decision, in one place.

    Three layers, and this is the third. The advisory is stored once; each CVE is its
    own entity; and every severity / CWE / affected / fix row is placed by EVIDENCE,
    not by convenience. Without that last step "one record links to several CVEs" is
    only a data structure - and a single 9.8 copied onto five CVEs would manufacture
    five complete-looking records out of one statement.

      entity_specific   the record speaks about exactly one vulnerability
      shared_explicit   the record states the assertion covers ALL listed CVEs; the
                        ONLY class allowed to appear against several entities, and so
                        the only one that must carry evidence
      record_level      advisory-level, not attributable to a CVE

      attributed                 an entity owns it
      ambiguous                  it could belong to one of these CVEs, and the record
                                 does not say which - stays at advisory level
      not_vulnerability_scoped   advisory narrative; it never belonged to a CVE

    `counts_toward_completeness` is derived, and H1/H2 read only that flag. Everything
    else is still shown when a CVE is queried - context is not evidence.

    On the evidence available here:
      - one linked entity            -> entity_specific
      - several linked entities, but the record's own NATIVE ID is one of those CVEs
        -> entity_specific to that CVE. The source issued this record under that
        number; the aliases to the others are sameness claims the identity layer
        already declined to honour, so they must not drag the assertions along
        either (osv:CVE-2021-47987 is the one such record in this cohort).
      - several linked entities, narrative field -> record_level /
        not_vulnerability_scoped
      - several linked entities, a single score or CWE -> record_level / ambiguous

    `shared_explicit` is never assigned here: no structured field in these three
    sources expresses "all of the CVEs listed above are fixed in v2.1". Deciding it
    would take reading advisory prose, and promoting OSV's advisory-level `affected`
    to shared would be exactly the inference the identity layer refused. The class
    exists for data that does state it; in this corpus it is 0.
    """
    if len(entity_ids) == 1:
        return [entity_ids[0]], 'entity_specific', 'attributed', 'single_entity_record'
    if native_cve_entity_id in entity_ids:
        return ([native_cve_entity_id], 'entity_specific', 'attributed',
                'record_native_id_is_this_cve')
    if kind in NARRATIVE_KINDS:
        return [], 'record_level', 'not_vulnerability_scoped', 'advisory_narrative'
    return [], 'record_level', 'ambiguous', 'no_per_cve_evidence_in_record'


def counts_toward_completeness(scope):
    """H1 completeness and H2 read this and nothing else."""
    return scope in ('entity_specific', 'shared_explicit')


COMPLETENESS_FIELDS = ('usable_severity', 'valid_cwe', 'affected_package',
                       'affected_configuration', 'affected_version_specification',
                       'fixed_version', 'summary_text', 'detailed_description')
OBSERVATION_STATUSES = ('direct_record', 'content_not_observed',
                        'absent_from_source')
# only these two text kinds exist in this corpus; an unrecognised one supplies
# NOTHING rather than being filed under whichever bucket is closest
TEXT_FIELD_TO_COMPLETENESS = {'notes': 'detailed_description',
                              'title': 'summary_text'}


EXTRA_TEXT_FIELDS = {'ghsa': ('description', '/description'),
                     'osv': ('details', '/details')}


def extra_texts(src, raw):
    """The detailed descriptions the FROZEN extractor drops on the floor.

    R26c-F1: `extract_ghsa` stores only `summary` yet marks `description` consumed
    (identity_extract.py:332); `extract_osv` does the same to `details` (:407). So
    the model said NVD had 10,000 detailed descriptions and GHSA and OSV had none -
    while every one of the 9,477 GHSA records carries a description with a median of
    1,263 characters, LONGER than NVD's 343, and 4,487 OSV records carry details.
    R27 would have concluded that only NVD describes anything, from an extraction
    bug. The hospital had the full report; the importer copied only its title.

    Why this lives here and not in the extractor: identity_extract.py is sealed by
    arm 1's policy_code_sha256_lf. Editing it fails that gate, and the seal stops
    meaning anything. This is not a second extractor - it re-implements no frozen
    rule, it only reads two raw fields the frozen one discards - so the frozen code
    stays byte-identical and arm 1 keeps passing, which is the machine-checkable
    proof that nothing frozen moved.

    NOTE for anyone citing v2 numbers: `consume()` credited these fields as retained
    while never storing them, so v2's retention metric is OVERSTATED for description
    and details. v2 is frozen and superseded; that is recorded, not fixed.
    """
    field = EXTRA_TEXT_FIELDS.get(src)
    if not field:
        return []
    key, pointer = field
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        return []
    return [{'field': 'notes', 'value': value, 'pointer': pointer,
             'original': value, 'status': 'provided',
             'rule': 'text.recovered_detailed_description'}]


NVD_CNA_RULE = 'affected.nvd_cna_affected'
NVD_BOUNDARY_RULE = 'remediation.nvd_stated_unaffected_boundary'


def _nvd_version_bounds(entry):
    """CVE-5.0 version entry -> the bounds vocabulary the rest of the model uses.

    A lone `version` of "0" is NOT a version specification: it says every version is
    in range, exactly like OSV's `introduced: "0"`, which
    `affected_version_specification` already refuses to count. Treating the two
    differently would make NVD look more specific than OSV for the same statement.
    """
    version = str(entry.get('version') or '').strip()
    bounds = {'start_including': None, 'start_excluding': None,
              'end_including': None, 'end_excluding': None}
    if version and version not in ('0', '*', '-'):
        bounds['start_including'] = version
    if entry.get('lessThan'):
        bounds['end_excluding'] = str(entry['lessThan'])
    if entry.get('lessThanOrEqual'):
        bounds['end_including'] = str(entry['lessThanOrEqual'])
    return bounds


# Exact strings, per source, each one a convention that source uses for "we did not
# identify a package". Nothing is matched by shape.
PLACEHOLDER_PACKAGE_NAMES = {
    'nvd': frozenset({'n/a:n/a'}),      # CNA filled both vendor and product with n/a
    'osv': frozenset({':unknown:'}),    # Android Security Bulletin convention
    'ghsa': frozenset(),
}


def is_placeholder_package(source, name):
    """Is this package name the source saying "we did not identify a package"?

    R27a3-P0: 640 NVD affected rows carry `n/a:n/a`, assembled from a CNA that filled
    both vendor and product with "n/a". `usable_completeness_fields` counted any
    non-empty string, so 168 CVE entities were credited with a package on the strength
    of a placeholder alone - "address: unknown" filed as an address supplied.

    R27b-P1: the first fix over-corrected. It matched by SHAPE - every colon-separated
    part being one of n/a, unknown, none, `-`, `*` - and `*` is not a missing value at
    all. The OSV schema gives it a meaning: a package name of `*` denotes every package
    in that ecosystem, which is information, not its absence. Matching by shape also
    invites a future source's legitimate package called `none` to vanish.

    So the rule is now an EXACT string per source. Measured on the frozen samples: no
    package name is `*` anywhere, and no bare single-token placeholder exists either,
    so narrowing changes no number in this corpus - it removes a way to be wrong later.
    (The full index carries only boolean flags, not package names, so the wider window
    cannot be checked from this repository; that is a limit of what is stored, not a
    result.)

    The raw value stays in the payload. The source did say `n/a`, and G21 reconciles
    what the source said; what changes is only whether that counts as a package.
    """
    if not name:
        return False
    return str(name).strip().lower() in PLACEHOLDER_PACKAGE_NAMES.get(source, frozenset())


def nvd_stated_unaffected_boundaries(entry):
    """EVERY version at which the CNA states the status turns to unaffected.

    The wording matters (R27a2 ruling). CVE schema defines `changes[].at` as the
    version at which the status CHANGES - not as a patch release. It can show that
    from this version the product is no longer affected; it cannot show that a fix
    caused it. So the value counts toward fixed_version and is reported as a stated
    unaffected boundary, never as a patch version.

    The parent guard is the second half of the ruling: a bare `status: unaffected`
    version entry is range semantics (`lessThan 6.7, unaffected` means everything below
    6.7 is fine) and one of them is not even a version (`"version": "OS update"`).
    Reading those as fixes would have invented 1,470 remediations.

    R27a3-P1: this used to return only the FIRST qualifying change per row, dropping 98
    of 619 events - and "first" meant first in document order, which the CVE record
    format explicitly warns against relying on ("clients must not assume changes[] is
    sorted"). All of them are retained now.
    """
    if entry.get('status') != 'affected':
        return []
    return [str(ch['at']) for ch in entry.get('changes') or []
            if ch.get('status') == 'unaffected' and ch.get('at')]


def nvd_cna_affected(raw, stated_boundary=True):
    """The `cve.affected` subtree the frozen extractor never opens.

    R27a2-P0: `extract_nvd` reads only `cve.configurations` (5,899 of 10,000 records),
    while 9,674 records carry CNA-supplied affected data - vendor, product, package
    name, purl, CPEs, version ranges and status-change boundaries. 3,775 records have
    affectedData and NO configurations, so they were counted as stating no package at
    all. The extractor's comment "NVD has no remediation field" is true of
    `configurations` and false of the record.

    Downstream, like extra_texts, because identity_extract.py is sealed by arm 1's
    policy_code_sha256_lf: editing it fails that gate and the seal stops meaning
    anything. Nothing frozen is re-implemented here - this reads fields the frozen
    code does not look at.

    `ecosystem` is deliberately left as 'cna' rather than derived from collectionURL:
    turning a registry URL into an ecosystem name is an inference, and npm eligibility
    for H2 stays sourced from the GHSA/OSV ecosystem fields that state it outright.
    """
    rows = []
    for ai, block in enumerate(raw.get('cve', {}).get('affected') or []):
        for di, data in enumerate(block.get('affectedData') or []):
            vendor = (data.get('vendor') or '').strip()
            product = (data.get('product') or '').strip()
            package = (f'{vendor}:{product}' if vendor and product
                       else (data.get('packageName') or product or vendor or None))
            ranges, boundaries = [], []
            for vi, entry in enumerate(data.get('versions') or []):
                bounds = _nvd_version_bounds(entry)
                ranges.append({'range_kind': 'bounds', 'range_type': 'CVE_CNA',
                               'bounds': bounds, 'comparator': 'cve_cna',
                               'original_expression': None})
                if stated_boundary:
                    boundaries += nvd_stated_unaffected_boundaries(entry)
            cpes = [c for c in (data.get('cpes') or []) if isinstance(c, str) and c]
            # A representative is still carried because remediation_profile and the H2
            # eligibility flag read a single value, but it is chosen by a DECLARED
            # deterministic rule rather than by document order. Sorting strings is not
            # a version comparison and is not claimed to be one - R27 asks only whether
            # a boundary exists, and `stated_unaffected_boundaries` keeps them all.
            representative = sorted(boundaries)[0] if boundaries else None
            rows.append({
                'package_name': package or None, 'ecosystem': 'cna',
                'purl': data.get('packageURL'),
                'cpe': cpes[0] if cpes else None, 'cpes': cpes,
                'ranges': ranges, 'first_patched_version': representative,
                'stated_unaffected_boundaries': sorted(boundaries),
                'remediation_kind': ('stated_unaffected_boundary' if boundaries
                                     else 'none'),
                'proxy_derived_from': None,
                'pointer': f'/cve/affected/{ai}/affectedData/{di}',
                'original': None, 'status': 'provided',
                'rule': NVD_BOUNDARY_RULE if boundaries else NVD_CNA_RULE})
    return rows


def range_signature(row):
    """Identity of an affected row for de-duplication, stable under key order."""
    return json.dumps([row.get('package_name'), row.get('first_patched_version'),
                       row.get('ranges')], sort_keys=True, ensure_ascii=False)


def duplicate_signatures(rows):
    """How many affected rows repeat another row's content, counted and NOT dropped.

    The first version of this de-duplicated: a CNA row whose (package, ranges, fix)
    matched an existing row was discarded. G21 caught it immediately - 357 raw
    affectedData pointers had no row in the model, e.g. Red Hat listing
    `Red Hat Enterprise Linux 7/8/9` as separate blocks that reduce to the same
    signature once versions are absent.

    Dropping them was wrong twice over. It destroys the one-to-one mapping from
    json_pointer to row that makes G21's reconciliation possible at all, and it throws
    away provenance: two blocks saying the same thing IS what the source published.
    The completeness fields are per-entity booleans, so repeats cannot inflate them.
    """
    seen, dupes = set(), 0
    for row in rows:
        sig = range_signature(row)
        dupes += sig in seen
        seen.add(sig)
    return dupes


def nvd_kev_texts(raw):
    """CISA KEV content NVD publishes inside the CVE record.

    Split on purpose (R27a2 ruling): `cisaVulnerabilityName` is a short title-form
    name and becomes summary_text; `cisaRequiredAction` is an instruction, not a
    summary and not a fixed version, so it is kept as its own text field and mapped to
    NO completeness field. Both carry content_provider so the sensitivity arm can
    exclude CISA-enriched content - H1 asks what a user can obtain from the database,
    not who first wrote it.
    """
    cve = raw.get('cve') or {}
    out = []
    for key, field, pointer in (('cisaVulnerabilityName', 'title', '/cve/cisaVulnerabilityName'),
                                ('cisaRequiredAction', 'remediation_action',
                                 '/cve/cisaRequiredAction')):
        value = cve.get(key)
        if isinstance(value, str) and value.strip():
            out.append({'field': field, 'value': value, 'pointer': pointer,
                        'original': value, 'status': 'provided',
                        'content_provider': 'CISA_KEV',
                        'rule': f'text.kev_{field}'})
    return out


OSV_CUSTOM_FIX_BLOCKS = (('ecosystem_specific', 'custom_ranges'),
                         ('database_specific', 'unresolved_ranges'))


def osv_custom_block_fixed_versions(raw):
    """Fix versions OSV records inside free-form blocks, as SENSITIVITY input only.

    R27a3-P1: `affected[].ecosystem_specific.custom_ranges` and
    `affected[].database_specific.unresolved_ranges` carry `events[].fixed` for records
    whose core-schema ranges have none - 26 CVE entities on this corpus. They are NOT
    folded into fixed_version, because the OSV schema states that the contents of these
    blocks are defined by each ecosystem or database rather than by the schema, so
    their semantics are not comparable across sources.

    What follows from that is a NAMING obligation as much as a counting one: the
    primary figure is OSV *core-schema* fixed-version completeness, not "OSV records
    that state a fix". The candidates are counted here so the sensitivity arm reads
    them from the model instead of re-reading the corpus.
    """
    out = {}
    for ai, aff in enumerate(raw.get('affected') or []):
        for block, key in OSV_CUSTOM_FIX_BLOCKS:
            ranges = ((aff.get(block) or {}) if isinstance(aff.get(block), dict)
                      else {}).get(key)
            for ri, rng in enumerate(ranges or []):
                if not isinstance(rng, dict):
                    continue
                for ev in rng.get('events') or []:
                    if isinstance(ev, dict) and ev.get('fixed'):
                        out.setdefault(f'{block}.{key}', []).append(
                            {'pointer': f'/affected/{ai}/{block}/{key}/{ri}',
                             'fixed': str(ev['fixed'])})
    return out


def osv_package_severities(raw):
    """Severity attached to a package entry instead of the record.

    Found by the R27a2 disposition audit, not by review: 133 records carry
    `affected[].severity[]` and every one of them has an EMPTY top-level `severity[]`,
    so 132 CVE-keyed records were losing their severity entirely. Same convention as
    the top-level block - OSV calls the field `score` and puts a CVSS vector in it.
    """
    out = []
    for ai, aff in enumerate(raw.get('affected') or []):
        for si, sev in enumerate(aff.get('severity') or []):
            value = sev.get('score')
            typ = (sev.get('type') or '').upper()
            scale = {'CVSS_V2': 'CVSS_V2', 'CVSS_V3': 'CVSS_V3_1',
                     'CVSS_V4': 'CVSS_V4_0'}.get(typ, 'OTHER')
            out.append({'scale': scale, 'score': None,
                        'vector': value if isinstance(value, str) else None,
                        'label': None,
                        'pointer': f'/affected/{ai}/severity/{si}/score',
                        'original': value,
                        'status': 'provided' if value else 'source_not_provided',
                        'rule': 'severity.osv_package_level'})
    return out


def osv_add_version_lists(raw, rows):
    """OSV states affected versions two ways; the frozen extractor reads only one.

    `affected[].versions` is an explicit enumeration. 7 records (4 CVE-keyed) give one
    with no `ranges` at all, so they were counted as stating no versions. Attached to
    the extractor's own row for the same `affected[]` index, by pointer, so nothing
    has to assume the two lists line up.
    """
    by_pointer = {r.get('pointer'): r for r in rows}
    added = 0
    for ai, aff in enumerate(raw.get('affected') or []):
        versions = [str(v) for v in (aff.get('versions') or []) if str(v).strip()]
        row = by_pointer.get(f'/affected/{ai}')
        if not versions or row is None:
            continue
        row['ranges'] = (row.get('ranges') or []) + [{
            'range_kind': 'version_list', 'range_type': 'VERSIONS',
            'bounds': None, 'comparator': 'enumeration',
            'events': [{'kind': 'affected_version', 'value': v} for v in versions],
            'original_expression': None}]
        added += 1
    return added


def split_cpe(cpe):
    """Split a CPE 2.3 string on its UNESCAPED colons.

    R26d-F2: a plain `split(':')` breaks on colons that are part of a component.
    Perl module names carry them constantly - `cpe:2.3:a:cosimo:net\\:\\:statsd:*:...`
    - and naive splitting puts a lone backslash in field 5, which then reads as a
    concrete version. 18 rows in the frozen sample contain escaped colons and 17 of
    them get the RIGHT answer for the WRONG reason (their explicit bounds decide it
    anyway); the remaining one lands on `1440` by luck. Nothing in today's output is
    wrong, and the parser is one refresh away from being wrong.
    """
    parts, buf, escaped = [], [], False
    for ch in cpe or '':
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == '\\':
            buf.append(ch)
            escaped = True
        elif ch == ':':
            parts.append(''.join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append(''.join(buf))
    return parts


def corrected_nvd_package(payload):
    """Re-derive an NVD package name from the CPE that was kept verbatim.

    R26e-F1: the frozen extractor builds `vendor:product` with the same naive
    `split(':')` that R26d fixed for the version field - and I fixed only the version
    field. 18 of 37,756 NVD affected rows carry a truncated name across 16 CVE
    entities: `cosimo:net\\:\\:statsd` was stored as `cosimo:net\\`, and
    `archive\\:\\:tar_project:archive\\:\\:tar` collapsed to `archive\\:\\` with
    vendor and product both misaligned.

    Nothing downstream of identity was harmed - `affected_package` only asks whether
    the name is non-empty, and a truncated name is still non-empty - but a package
    name that is not the source's package name breaks package lookup and H2.

    The full CPE was always retained, so this is recoverable here, in v3, without
    touching the sealed extractor.

    The escapes are KEPT. `net\\:\\:statsd` is how CPE 2.3 encodes `net::statsd`;
    turning one into the other is a separate normalisation decision and is not taken
    here.
    """
    crit = payload.get('cpe') or ''
    if not crit:
        return payload.get('package_name')
    parts = split_cpe(crit)
    vendor = parts[3] if len(parts) > 3 else ''
    product = parts[4] if len(parts) > 4 else ''
    return f'{vendor}:{product}' if vendor and product else (crit or None)


def concrete_cpe_version(cpe):
    """Does this CPE name a specific affected version?

    CPE 2.3 puts the version in field 5:
        cpe:2.3:a:vendor:product:VERSION:update:...
    `*` (any) and `-` (not applicable) are not versions. Everything else is - and
    `1.0` is very specific information even though it is not written as an interval.
    """
    parts = split_cpe(cpe)
    if len(parts) <= 5:
        return False
    return parts[5] not in ('*', '-', '')


def affected_version_specification(payload):
    """Does this row say WHICH versions are affected - by any means the source uses?

    R26c-F2: the predicate previously accepted only start/end boundaries, so NVD's
    26,059 boundary-free rows all counted as "configuration only". They are not one
    thing: 14,745 pin a specific version in the CPE itself
    (cpe:2.3:a:vendor:product:1.0:*) and 11,314 are genuinely wildcard (`*` or `-`).
    An exact affected version is very specific information even though it is not
    written as an interval, so NVD's version-bearing rows are 11,697 + 14,745 =
    26,442. Hence the rename: this is a version SPECIFICATION, not a bounded range.

      nvd   start/end bounds, or a concrete version in the CPE, or CNA-supplied
            version / lessThan / lessThanOrEqual (R27a2)
      ghsa  a non-empty vulnerable_version_range expression
      osv   fixed / last_affected / limit, an introduced other than "0", or an
            explicit affected[].versions enumeration (R27a2)
      none  wildcard CPE with no bounds; `introduced: "0"` alone; a CNA version entry
            of "0" with no upper bound - it says every version, same as introduced 0

    The `range_kind == 'text'` guard stays: NVD keeps its CPE string in
    original_expression (identity_extract.py:229), and reading that as a version
    expression is the mistake that made NVD look fully bounded in R26b.
    """
    if payload.get('first_patched_version'):
        return True
    if concrete_cpe_version(payload.get('cpe')):
        return True                           # NVD: an exact affected version
    for rg in payload.get('ranges') or []:
        if any(v for v in (rg.get('bounds') or {}).values()):
            return True                       # NVD versionStart*/versionEnd*
        if (rg.get('range_kind') == 'text'
                and (rg.get('original_expression') or '').strip()):
            return True                       # GHSA ">= 7.4.0, <= 7.4.3.131"
        if rg.get('range_kind') == 'version_list' and (rg.get('events') or []):
            return True                       # OSV affected[].versions enumeration
        for e in rg.get('events') or []:
            if e.get('kind') in ('fixed', 'last_affected', 'limit'):
                return True
            if (e.get('kind') == 'introduced'
                    and str(e.get('value') or '').strip() not in ('', '0')):
                return True
    return False


def usable_completeness_fields(kind, item, source=None):
    """Which completeness fields this assertion actually SUPPLIES A VALUE for.

    R26-F1: `counts_toward_completeness` says an assertion can be attributed to an
    entity. It says nothing about whether the field carries anything usable, and on
    this corpus that gap is large:

      8,254 GHSA severity blocks are placeholders - {vector_string: null, score: 0.0}
      written for a scale the advisory did not populate. Another ~8,900 rows are
      NVD SSVC entries with neither a numeric score nor a vector, marked `provided`.
      17,131 of 47,034 severity rows carry no usable value at all.

      415 NVD CWE rows are sentinels (NVD-CWE-noinfo and friends) - a statement that
      no CWE is known, not a CWE.

      90,481 affected rows carry no fixed version. A package and a vulnerable range
      are real information, but they are not remediation, and `affected` as one
      field hid the difference.

    So the vocabulary is six fields, and one `affected` row may supply three of them
    independently. Presence of a row is not presence of a value.
    """
    if kind == 'severity':
        if item.get('status') == 'placeholder':
            return []
        score = item.get('score')
        numeric = isinstance(score, (int, float)) and not isinstance(score, bool)
        return ['usable_severity'] if numeric or item.get('vector') else []
    if kind == 'cwe':
        return (['valid_cwe'] if item.get('value') and not item.get('is_sentinel')
                else [])
    if kind == 'affected':
        out = []
        # R27a3-P0: a package name the source filled with `n/a` is the source saying it
        # did not identify a package. Counting it inflated NVD by 168 entities.
        # R27b-P1: judged per source by exact string - `*` is a real OSV package
        # expression meaning every package in the ecosystem, not a missing value.
        if item.get('package_name') and not is_placeholder_package(
                source, item['package_name']):
            out.append('affected_package')
        if item.get('ranges'):
            out.append('affected_configuration')
        if affected_version_specification(item):
            out.append('affected_version_specification')
        if item.get('first_patched_version'):
            out.append('fixed_version')
        return out
    if kind == 'text':
        if not (item.get('value') or '').strip():
            return []
        # R26b-F3: NVD supplies `notes` (median 343 characters), GHSA and OSV supply
        # `title` (median 79 and 57). Scoring both as one "description" field would
        # have NVD's detailed text and GHSA's headline count as the same thing.
        got = TEXT_FIELD_TO_COMPLETENESS.get(item.get('field'))
        return [got] if got else []
    return []


def standalone_key(src, native_id):
    """The key a record with no CVE is filed under.

    The SOURCE is part of the key, and that is the whole of rule 4: two registries
    using the same string for different advisories must not collapse into one entity
    just because the strings match. One named place, so a gate can perturb it.
    """
    return f'native:{src}:{native_id}'


def remediation_profile(affected_rows):
    """Is there enough here to act on - a package, and a version that fixes it?

    H2 is scoped to npm/Node.js, so `npm_actionable` is the eligibility flag it reads.
    A no-CVE advisory qualifies on exactly the same terms as a CVE one: the ID number
    decides which comparison a record can join, not whether its remediation is usable.
    Field names are the extractor's (identity_extract.py:373-396), not invented here.
    """
    ecosystems, fixed, packaged = set(), 0, 0
    npm_rows = 0
    for a in affected_rows:
        eco = (a.get('ecosystem') or '').strip()
        if eco:
            ecosystems.add(eco)
        has_pkg = bool(a.get('package_name'))
        has_fix = bool(a.get('first_patched_version'))
        packaged += bool(has_pkg)
        fixed += bool(has_fix)
        if has_pkg and has_fix and eco.lower() == 'npm':
            npm_rows += 1
    return {
        'affected_rows': len(affected_rows),
        'ecosystems': sorted(ecosystems)[:10],
        'rows_with_package_name': packaged,
        'rows_with_fixed_version': fixed,
        'npm_rows_with_package_and_fix': npm_rows,
        'npm_actionable': npm_rows > 0,
    }


def back_query_index(input_dir):
    """The full index, read ONCE, as a CVE -> sources lookup. Never a denominator.

    Rule 6. This answers "does any source hold a record for this CVE outside the
    frozen cohort", which is what coverage_map's back-query column reports. It adds
    no records, no entities and no rows to any analysis population - the three
    denominators are reported alongside so the separation is visible rather than
    promised.
    """
    by_cve = defaultdict(set)
    physical = Counter()
    per_source_ids = defaultdict(set)
    for src in SOURCES:
        path = input_dir / f'{src}_full_index.jsonl.gz'
        for row in iter_jsonl_gz(path):
            physical[src] += 1
            nid = norm(row.get('id'))
            if not nid:
                continue
            per_source_ids[src].add(nid)
            if CVE_RE.match(nid):
                by_cve[nid].add(src)
            for a in row.get('aliases') or []:
                a = norm(a)
                if a and CVE_RE.match(a):
                    by_cve[a].add(src)
    denominators = {
        'physical_rows': sum(physical.values()),
        'physical_rows_by_source': dict(sorted(physical.items())),
        'per_source_deduped': sum(len(v) for v in per_source_ids.values()),
        'across_source_unique_native_ids': len(set().union(*per_source_ids.values())),
        'note': ('reported for provenance only; rule 6 keeps every one of these out '
                 'of the analysis denominator'),
    }
    return {k: sorted(v) for k, v in by_cve.items()}, denominators


def build(input_dir=DEFAULT_IN, out_dir=DEFAULT_OUT, quiet=False, back_query=None,
          mapping=None):
    """`back_query` may carry an already-read `(cve_index, denominators)` pair.

    Only so a gate injecting a dozen faults does not re-stream 1.19M index rows each
    time. The end-to-end determinism check builds twice WITHOUT it, so the index read
    is still covered rather than assumed.
    """
    mapping = switches() if mapping is None else switches(**mapping)

    def say(*a):
        if not quiet:
            print(*a)

    source_records, links, relations = [], [], []
    sev_rows, cwe_rows, aff_rows, gen_rows = [], [], [], []
    entity_kind = {}                       # entity_id -> kind
    entity_pref = {}                       # entity_id -> preferred identifier
    entity_records = defaultdict(list)     # entity_id -> [record_ref]
    entity_sources = defaultdict(set)
    entity_sevs = defaultdict(list)
    entity_affected = defaultdict(list)
    entity_fields = defaultdict(Counter)   # only rows that count toward completeness
    entity_source_fields = defaultdict(lambda: defaultdict(set))
    scope_counts = Counter()
    unattributable = []
    norm_events = 0
    nvd_package_reparsed = 0
    recovered = Counter()
    sensitivity_records = {}   # record_ref -> custom-block fix candidates
    cve_per_record = Counter()
    record_counts_by_source = Counter()

    for src in SOURCES:
        path = input_dir / f'sample_{src}.jsonl.gz'
        for raw in iter_jsonl_gz(path):
            ex = EXTRACTORS[src](raw)
            if src == 'nvd':
                # R26e-F1: repair the package name in place, before anything reads
                # it. The frozen extractor split the CPE naively; the CPE itself was
                # kept, so the correct vendor:product is recoverable here.
                for a in ex.get('affected') or []:
                    fixed = corrected_nvd_package(a)
                    if fixed != a.get('package_name'):
                        nvd_package_reparsed += 1
                        a['package_name'] = fixed
                # R27a2-P0: the CNA affected subtree the extractor never opens
                cna = nvd_cna_affected(
                    raw, stated_boundary=mapping['nvd_stated_boundary'])
                if cna:
                    recovered['nvd_cna_affected_rows'] += len(cna)
                    recovered['nvd_records_with_cna_affected'] += 1
                    recovered['nvd_cna_rows_repeating_another_row'] += \
                        duplicate_signatures((ex.get('affected') or []) + cna)
                    ex['affected'] = (ex.get('affected') or []) + cna
                    if any(r.get('first_patched_version') for r in cna):
                        recovered['nvd_records_with_stated_unaffected_boundary'] += 1
            if src == 'osv':
                # R27a2: severity attached to a package, and explicit version lists
                pkg_sev = osv_package_severities(raw)
                if pkg_sev:
                    recovered['osv_package_severity_rows'] += len(pkg_sev)
                    if not (ex.get('severities') or []):
                        recovered['osv_records_whose_only_severity_is_package_level'] += 1
                    ex['severities'] = (ex.get('severities') or []) + pkg_sev
                attached = osv_add_version_lists(raw, ex.get('affected') or [])
                if attached:
                    recovered['osv_version_lists_attached'] += attached
                    recovered['osv_records_with_version_list'] += 1
            nid = norm(ex.get('native_id'))
            if not nid:
                continue
            ref = f'{src}:{nid}'
            # NB: this must come AFTER `ref` exists. It first went above, where `ref`
            # still held the PREVIOUS record's value - the count came out right and
            # every key was wrong, which is the kind of defect that only shows up when
            # something downstream tries to use the keys.
            if src == 'osv':
                custom_fix = osv_custom_block_fixed_versions(raw)
                if custom_fix:
                    sensitivity_records[ref] = custom_fix
                    if mapping['osv_custom_fixed']:
                        # the declared sensitivity arm: fold the custom-block fixes
                        # into the affected rows they belong to
                        by_ptr = {r.get('pointer'): r
                                  for r in ex.get('affected') or []}
                        for origin, hits in custom_fix.items():
                            for hit in hits:
                                ai = hit['pointer'].split('/')[2]
                                row = by_ptr.get(f'/affected/{ai}')
                                if row and not row.get('first_patched_version'):
                                    row['first_patched_version'] = hit['fixed']
                                    row['remediation_kind'] = (
                                        'osv_custom_block_fixed')
                                    row['rule'] = f'remediation.osv_{origin}'
            record_counts_by_source[src] += 1
            raw_sha = sha256_obj(raw)
            cves = normalised_cves(ex.get('cves'))
            norm_events += sum(1 for c in (ex.get('cves') or [])
                               if isinstance(c, str) and c != norm(c))
            cve_per_record[len(cves)] += 1
            bases = cve_bases(src, raw)

            # ---- entities and links. Rule 2/3/4 live here and nowhere else.
            eids = []
            for cve in cves:
                eid = entity_id_for(cve)
                entity_kind[eid] = 'cve'
                entity_pref[eid] = cve
                eids.append(eid)
                links.append({'entity_id': eid, 'record_ref': ref, 'source': src,
                              'native_id': nid, 'cve': cve,
                              'link_bases': bases.get(cve, []),
                              'link_kind': 'cve_entity'})
            if not cves:
                # a record with no ID number is filed under its own name, and the
                # name says which registry issued it
                standalone = standalone_key(src, nid)
                eid = entity_id_for(standalone)
                entity_kind[eid] = 'no_direct_cve_identity'
                entity_pref[eid] = standalone
                eids.append(eid)
                links.append({'entity_id': eid, 'record_ref': ref, 'source': src,
                              'native_id': nid, 'cve': None, 'link_bases': [],
                              'link_kind': 'no_direct_cve_identity'})
            for eid in eids:
                entity_records[eid].append(ref)
                entity_sources[eid].add(src)

            for r in declared_relations(src, raw, set(cves)):
                relations.append({'record_ref': ref, 'source': src,
                                  'native_id': nid, **r})

            # the record's own native id, when it IS one of the declared CVEs
            native_cve_eid = (entity_id_for(nid)
                              if CVE_RE.match(nid) and nid in cves else None)

            def emit(kind, items, sink, shape):
                targets, scope, status, evidence = classify_assertion(
                    kind, eids, native_cve_eid)
                counts = counts_toward_completeness(scope)
                for item in items or []:
                    supplies = usable_completeness_fields(kind, item, src)
                    # two booleans, deliberately kept apart: "cannot be attributed"
                    # and "carries no usable value" are different absences, and R27
                    # needs to tell them apart
                    contributes = bool(counts and supplies)
                    base = {'record_ref': ref, 'source': src, 'native_id': nid,
                            'assertion_kind': kind, 'assertion_scope': scope,
                            'attribution_status': status,
                            'attribution_evidence': evidence,
                            'counts_toward_completeness': counts,
                            'usable_fields': supplies,
                            'has_usable_value': bool(supplies),
                            'contributes_completeness_field': contributes,
                            'raw_record_sha256': raw_sha, **shape(item)}
                    # targets is empty for record-level rows: one row, entity_id null.
                    # It holds SEVERAL ids only for shared_explicit, the one class the
                    # sources may state and the only legitimate duplication.
                    scope_counts[(kind, scope, status)] += 1
                    if not counts:
                        unattributable.append(
                            {'record_ref': ref, 'assertion_kind': kind,
                             'assertion_scope': scope, 'attribution_status': status,
                             'json_pointer': base.get('json_pointer'),
                             'declared_cves': cves})
                    for eid in (targets or [None]):
                        sink.append({**base, 'entity_id': eid})
                        if not eid:
                            continue
                        if kind == 'severity':
                            entity_sevs[eid].append(item)
                        if kind == 'affected':
                            entity_affected[eid].append(item)
                        if counts:
                            entity_fields[eid][kind] += 1
                        if contributes:
                            entity_source_fields[eid][src].update(supplies)

            emit('severity', ex.get('severities'), sev_rows, lambda s: {
                'scale': s.get('scale'), 'score': s.get('score'),
                'vector': s.get('vector'), 'label': s.get('label'),
                'status': s.get('status'), 'json_pointer': s.get('pointer'),
                'transform_rule': s.get('rule')})
            emit('cwe', ex.get('cwes'), cwe_rows, lambda c: {
                'value': c.get('value'), 'is_sentinel': c.get('is_sentinel'),
                'json_pointer': c.get('pointer'), 'transform_rule': c.get('rule')})
            emit('affected', ex.get('affected'), aff_rows, lambda a: {
                'payload': a, 'json_pointer': a.get('pointer')})
            kev = (nvd_kev_texts(raw)
                   if src == 'nvd' and mapping['nvd_kev_texts'] else [])
            if kev:
                recovered['nvd_kev_text_rows'] += len(kev)
                recovered['nvd_records_with_kev_text'] += 1
            emit('text', (ex.get('texts') or []) + extra_texts(src, raw) + kev,
                 gen_rows, lambda t: {'payload': t})
            emit('warning', ex.get('warnings'), gen_rows, lambda w: {'payload': w})

            source_records.append({
                'record_ref': ref, 'source': src, 'native_id': nid,
                'raw_record_sha256': raw_sha, 'declared_cves': cves,
                'declared_cve_count': len(cves), 'entity_ids': sorted(eids),
                'published': ex.get('published'), 'modified': ex.get('modified')})

    say(f'[v3] ingested {len(source_records):,} records '
        f'{dict(sorted(record_counts_by_source.items()))}')

    # ---- back-query (rule 6): coverage only, never a denominator
    if back_query is None:
        say('[v3] reading the full index for back-query ...')
        cve_index, denominators = back_query_index(input_dir)
    else:
        cve_index, denominators = back_query

    entities, no_numeric = [], 0
    for eid in sorted(entity_kind):
        derived, skipped = derived_severity(entity_sevs.get(eid) or [])
        if not derived:
            no_numeric += 1
        entities.append({
            'entity_id': eid, 'preferred_identifier': entity_pref[eid],
            'entity_kind': entity_kind[eid],
            # the two H1 strata. A record with no CVE is still normalised, still
            # retrievable and still H2-eligible; it just cannot take part in
            # CVE-keyed cross-source pairing, so it is reported separately rather
            # than mixed into a comparison it cannot be part of.
            'stratum': ('cve_keyed' if entity_kind[eid] == 'cve'
                        else 'no_direct_cve_identity'),
            'record_count': len(entity_records[eid]),
            'source_count': len(entity_sources[eid]),
            'derived_severity_max_by_scale': derived,
            'derived_severity_excluded': skipped,
            'actionable_remediation': remediation_profile(
                entity_affected.get(eid) or [])})

    coverage = []
    for e in entities:
        eid, pref = e['entity_id'], e['preferred_identifier']
        direct = sorted(entity_sources[eid])
        bq = cve_index.get(pref, []) if e['entity_kind'] == 'cve' else []
        fields = entity_fields.get(eid) or Counter()
        coverage.append({
            'entity_id': eid, 'preferred_identifier': pref,
            'entity_kind': e['entity_kind'], 'stratum': e['stratum'],
            # R27 reads THIS and not the raw assertion counts: only rows that count
            # toward completeness are here, so an advisory-level score can never be
            # mistaken for evidence about a particular CVE.
            'completeness_fields_present': {
                k: fields.get(k, 0) for k in
                ('severity', 'cwe', 'affected', 'text', 'warning')},
            'completeness_field_kinds': sorted(k for k in fields if fields[k]),
            'npm_actionable': e['actionable_remediation']['npm_actionable'],
            'direct_sources': direct, 'direct_source_count': len(direct),
            'direct_record_refs': sorted(entity_records[eid]),
            'back_query_sources': bq,
            'back_query_only_sources': sorted(set(bq) - set(direct)),
            'back_query_status': ('not_applicable_no_cve'
                                  if e['entity_kind'] != 'cve' else
                                  'found' if bq else 'absent_from_full_index')})

    # ---- per-source completeness matrix (CVE-keyed stratum only)
    #
    # R26-F2: coverage_map aggregates sources into one entity-level answer, and the
    # back-query only says WHICH sources hold a CVE - never what their records
    # contain. That can show coverage and cannot show completeness.
    #
    # The three observation statuses are the point. 11,175 entities have a source
    # that holds the CVE while this snapshot never collected the record: scoring
    # those as "field missing" would understate every single-source column by
    # thousands of entities. They are `content_not_observed`, and their field
    # booleans are null - not false.
    matrix = []
    for e in entities:
        if e['stratum'] != 'cve_keyed':
            continue
        eid, cve = e['entity_id'], e['preferred_identifier']
        direct = entity_sources[eid]
        holders = set(cve_index.get(cve, []))
        source_cells = {}
        for s in SOURCES:
            if s in direct:
                got = entity_source_fields[eid][s]
                source_cells[s] = {
                    'observation_status': 'direct_record',
                    'fields': {f: (f in got) for f in COMPLETENESS_FIELDS}}
            else:
                seen_here = s in holders
                source_cells[s] = {
                    'observation_status': ('content_not_observed' if seen_here
                                           else 'absent_from_source'),
                    # null, not false: nothing was observed, so nothing is missing
                    'fields': {f: None for f in COMPLETENESS_FIELDS}}
        union = {f: any(source_cells[s]['fields'][f] is True for s in SOURCES)
                 for f in COMPLETENESS_FIELDS}
        matrix.append({
            'entity_id': eid, 'cve': cve, 'stratum': e['stratum'],
            'by_source': source_cells,
            'unified': {'fields': union,
                        'basis': 'union over direct_record sources only'},
            'direct_sources': sorted(direct),
            'sources_observed': sum(1 for s in SOURCES
                                    if source_cells[s]['observation_status']
                                    == 'direct_record'),
            'sources_not_observed': sum(
                1 for s in SOURCES
                if source_cells[s]['observation_status']
                == 'content_not_observed')})

    # ---- no-CVE descriptive matrix (the OTHER stratum, R27a2-P1)
    #
    # The protocol requires the 9,528 no-CVE entities to be reported as their own
    # layer, and the CVE matrix above deliberately excludes them - so §8 of the
    # protocol had nothing to read. This section gives them the same per-source field
    # shape and NOTHING ELSE: no co-observation, no union, no pairing. Two registries
    # that both lack a CVE number cannot be assumed to describe the same vulnerability,
    # so a paired comparison here would compare things never shown to be comparable.
    matrix_no_cve = []
    for e in entities:
        if e['stratum'] == 'cve_keyed':
            continue
        eid = e['entity_id']
        direct = sorted(entity_sources[eid])
        matrix_no_cve.append({
            'entity_id': eid, 'preferred_identifier': e['preferred_identifier'],
            'stratum': e['stratum'],
            'source': direct[0] if len(direct) == 1 else None,
            'direct_sources': direct,
            'fields': {f: (f in entity_source_fields[eid][direct[0]])
                       for f in COMPLETENESS_FIELDS} if len(direct) == 1 else
                      {f: any(f in entity_source_fields[eid][s] for s in direct)
                       for f in COMPLETENESS_FIELDS},
            'basis': ('single source, by construction: a no-CVE entity is keyed by '
                      'native:<source>:<id>, so it can never span sources'),
            'npm_actionable': e['actionable_remediation']['npm_actionable']})

    sections = {
        'entities': entities,
        'completeness_matrix': matrix,
        'completeness_matrix_no_cve': matrix_no_cve,
        'source_records': sorted(source_records, key=lambda r: r['record_ref']),
        'entity_record_links': sorted(
            links, key=lambda r: (r['entity_id'], r['record_ref'])),
        'relations': sorted(relations, key=lambda r: (
            r['record_ref'], r['relation_type'], r['target'])),
        'assertions_severity': sev_rows, 'assertions_cwe': cwe_rows,
        'assertions_affected': aff_rows, 'assertions_generic': gen_rows,
        'coverage_map': coverage,
    }
    assert set(sections) == set(SECTIONS), 'SECTIONS is out of sync with the writer'

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, rows in sections.items():
        write_jsonl_gz(out_dir / f'{name}.jsonl.gz', rows)

    inputs = {}
    for s in SOURCES:
        for stem in (f'sample_{s}', f'{s}_full_index'):
            p = input_dir / f'{stem}.jsonl.gz'
            h = hashlib.sha256()
            with open(p, 'rb') as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b''):
                    h.update(chunk)
            inputs[p.name] = h.hexdigest()

    kinds = Counter(e['entity_kind'] for e in entities)
    strata = defaultdict(Counter)
    for e in entities:
        strata[e['stratum']]['entities'] += 1
        if e['actionable_remediation']['npm_actionable']:
            strata[e['stratum']]['npm_actionable'] += 1
    for c in coverage:
        if c['direct_source_count'] > 1:
            strata[c['stratum']]['entities_in_more_than_one_source'] += 1
        for s in c['direct_sources']:
            strata[c['stratum']][f'direct_{s}'] += 1
    # ---- what R27 must compute, and on which denominator (R26b-F2)
    #
    # All three columns have 17,695 rows, but that is the same CVE ROW UNIVERSE, not
    # the same effective observation denominator: NVD directly observed 10,000 of
    # them, GHSA 8,067, OSV 1,842. Dividing any source's field counts by 17,695 would
    # charge it for records this snapshot never collected.
    observed = {s: sum(1 for r in matrix
                       if r['by_source'][s]['observation_status'] == 'direct_record')
                for s in SOURCES}
    pair_sets = Counter()
    for r in matrix:
        obs = tuple(s for s in SOURCES
                    if r['by_source'][s]['observation_status'] == 'direct_record')
        pair_sets['+'.join(obs) or '(none)'] += 1
    r27_inputs = {
        'cve_row_universe': len(matrix),
        'directly_observed_by_source': observed,
        'observed_source_combinations': dict(sorted(pair_sets.items())),
        'entities_observed_by_more_than_one_source': sum(
            n for k, n in pair_sets.items() if '+' in k),
        'denominator_note': (
            f'{len(matrix)} is the CVE row universe, NOT any source\'s observation '
            'denominator. A per-source field rate must divide by that source\'s '
            'directly_observed count; a pairing gain must be computed only on the '
            'subset both sources observed'),
        'three_quantities_r27_must_separate': [
            'source coverage status over all CVE rows: direct_record / '
            'content_not_observed / absent_from_source',
            'field completeness WITHIN each source\'s directly observed records, '
            'denominator = that source\'s directly_observed count',
            'pairing gain: for CVEs observed by two or three sources, what the union '
            'adds over each single source, computed ONLY on that co-observed subset',
        ],
        'not_computed_here': ('the R26 series builds inputs. Effect sizes, '
                              'significance and any '
                              'claim that H1 holds belong to R27'),
    }

    meta = {
        'model_version': MODEL_VERSION,
        'assertion_contract': ASSERTION_CONTRACT,
        'r27_inputs': r27_inputs,
        'supersedes': ('2.3.0-identity, which is NOT overwritten: it stays as '
                       'engineering history and a supplementary sensitivity arm'),
        # Section E's principle applied to the other direction: someone opening this
        # file must see at a glance that the build is sealed, not have to find the
        # worklog that says so. The manifest is named rather than hashed - it records
        # the sealing COMMIT, which cannot exist until this build is committed, so
        # hashing it here would be circular (hence the follow-up commit, section D).
        'build_status': 'sealed_h1',
        'sealed_scope': [
            'identity layer (CVE-keyed; 17,695 CVE + 9,528 no-direct-CVE entities)',
            'field mapping (schemas/SOURCE_FIELD_DISPOSITION.json, all observed paths)',
            'completeness_matrix and completeness_matrix_no_cve (content-sealed)',
            'R27 primary results and R28 sensitivity arms',
        ],
        'sealed_by_manifest': 'h1_seal_manifest.json',
        'reopening_note': ('changing an identity rule or a field mapping REOPENS H1. '
                           'It must be an explicit round, never a silent edit'),
        'identity_contract': IDENTITY_CONTRACT,
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'built_at_note': ('every .jsonl.gz section is byte-identical across rebuilds; '
                          'dataset_metadata.json is not, because generated_at_utc '
                          'holds the wall-clock time of this build'),
        'input_dir': str(input_dir), 'inputs': inputs,
        'cohort': {
            'source_records': len(source_records),
            'record_counts_by_source': dict(sorted(record_counts_by_source.items())),
            'cve_entities': kinds['cve'],
            'no_direct_cve_identity_entities': kinds['no_direct_cve_identity'],
            'entities_total': len(entities),
            'records_by_declared_cve_count': dict(sorted(cve_per_record.items())),
            'multi_cve_records': sum(v for k, v in cve_per_record.items() if k > 1),
            'entity_record_links': len(links),
            'relations': len(relations),
            'entities_without_a_numeric_severity': no_numeric,
            'cve_normalisation_events': norm_events,
            'nvd_package_names_reparsed': nvd_package_reparsed,
            # R27a2: content the frozen extractor never read, recovered downstream.
            # Counted rather than folded in silently - a mapping change that moves the
            # completeness numbers has to be visible as its own line.
            'recovered_by_downstream_mapping': dict(sorted(recovered.items())),
        },
        # R27a3-P1: inputs for declared SENSITIVITY arms, never for the primary
        # figures. Kept here so the analysis reads the model rather than re-reading
        # the corpus, and so the gate can reconcile them against the raw samples.
        'sensitivity_candidates': {
            'osv_fixed_version_from_custom_blocks': {
                'note': ('OSV states that the contents of ecosystem_specific and '
                         'database_specific are defined by each ecosystem or database, '
                         'not by the schema, so these are NOT folded into '
                         'fixed_version. The primary figure is OSV CORE-SCHEMA '
                         'fixed-version completeness'),
                'records': len(sensitivity_records),
                'by_origin': dict(sorted(Counter(
                    origin for v in sensitivity_records.values()
                    for origin in v).items())),
                'cve_entities_that_would_gain': sorted(
                    {eid for r in source_records if r['record_ref'] in sensitivity_records
                     for eid in r['entity_ids']
                     if entity_kind.get(eid) == 'cve'
                     and 'fixed_version' not in entity_source_fields[eid]['osv']}),
            },
        },
        'assertion_layers': {
            'by_kind_scope_status': {
                f'{k}|{s}|{a}': n for (k, s, a), n in sorted(scope_counts.items())},
            'totals_by_scope': dict(sorted(Counter(
                s for (_, s, _), n in scope_counts.items()
                for _ in range(n)).items())),
            'counting_toward_completeness': sum(
                n for (_, s, _), n in scope_counts.items()
                if counts_toward_completeness(s)),
            'not_counting': sum(n for (_, s, _), n in scope_counts.items()
                                if not counts_toward_completeness(s)),
            'unattributable_rows': sorted(
                unattributable, key=lambda r: (r['record_ref'],
                                               r['assertion_kind'],
                                               r['json_pointer'] or '')),
            'note': ('every row that does not count is listed in full above - there '
                     'are few enough to enumerate, and a class nobody can inspect is '
                     'a class nobody can challenge'),
        },
        'h1_strata': {k: dict(sorted(v.items())) for k, v in sorted(strata.items())},
        'full_index_denominators': denominators,
        'counts': {k: len(v) for k, v in sections.items()},
        'section_sha256': {name: hashlib.sha256(
            (out_dir / f'{name}.jsonl.gz').read_bytes()).hexdigest()
            for name in SECTIONS},
    }
    (out_dir / 'dataset_metadata.json').write_text(
        json.dumps(meta, indent=1, ensure_ascii=False, sort_keys=True),
        encoding='utf-8')
    say(f"[v3] {kinds['cve']:,} CVE entities + {kinds['no_direct_cve_identity']:,} "
        f"no-CVE independent = {len(entities):,} entities; "
        f"{len(links):,} links, {len(relations):,} relations")
    say(f'[v3] wrote {len(sections)} sections + dataset_metadata.json to {out_dir}')
    return {'sections': sections, 'meta': meta}


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--input-dir', default=str(DEFAULT_IN))
    ap.add_argument('--out-dir', default=str(DEFAULT_OUT))
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--mapping', metavar='NAME=on|off', action='append', default=[],
                    help='flip a declared mapping switch for a sensitivity arm')
    a = ap.parse_args()
    overrides = {}
    for item in a.mapping:
        name, _, value = item.partition('=')
        overrides[name] = value.lower() in ('on', 'true', '1', 'yes')
    build(Path(a.input_dir), Path(a.out_dir), a.quiet, mapping=overrides or None)
    return 0


if __name__ == '__main__':
    sys.exit(main())
