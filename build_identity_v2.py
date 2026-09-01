#!/usr/bin/env python3
"""Identity Layer v2 - identity-only builder.

Reads ONLY the three frozen sample files. No network. No presence matrix. No old
component table.

Why v2 exists (measured on the v1 build, marked known_bad_superseded): v1 kept
`upstream` out of the identity_edges it emitted, then looked entities up in the OLD
`id_to_component` table - which build_sample_matrix.py had built from alias UNION
upstream. upstream walked back in through the back door: 5,220 upstream-only OSV
records took a primary entity link, two record roles were dead code, 1,411 of 2,156 OSV
aliases never became an edge, and 12,874 assertions collapsed into one pseudo-entity
keyed entity_id=None.

Round 9 review then rejected the first v2 candidate. The upstream back door was
genuinely closed, but the entity policy contradicted itself and the acceptance gate was
weaker than it claimed. What changed here:

* ENTITY POLICY D (round 9 decision, supersedes spec section 3's "split every
  multi-CVE component"). An entity is issued for a CVE only when some record actually
  CARRIES it - the record's own native id, GHSA's own cve_id, or the single CVE among
  its aliases. A CVE that is merely mentioned in someone's alias list is a CVE whose
  record we never received, exactly like spec section 3's referenced-only CVEs, and it
  gets no entity.
  This matters because `aliases` is NOT reliably same-vulnerability in this corpus.
  Manual inspection of all 4 multi-CVE components found 2 of them aliasing DISTINCT
  vulnerabilities batched into one advisory - GHSA-365w is titled "Crawl4AI: Multiple
  Docker API Vulnerabilities - File Write, SSRF, Auth Bypass, XSS, JS Execution" and
  PYSEC-2026-596 describes only the SSRF while aliasing all five CVEs. Merging one
  entity per component would have re-created v1's over-merge from the alias side;
  splitting per CVE created 8 entities no record claims. Policy D does neither.
* RELATIONS ARE CONSERVED. Links deduplicate on the full
  (record_ref, referenced_id, link_role, link_basis) key. The previous 2-key dedup
  silently dropped 4,961 distinct relations, and the "no fan-out" check that quoted
  those row counts was vacuous - it asserted the dedup had worked.
* Identifiers are trimmed, anchors prefer a source-native id, and no claim of
  cross-snapshot stability is made: ids are deterministic for a given member set.

Round 11 review then found that policy D had removed the phantom entities without
stopping the over-merge underneath them. Every alias still entered the union, so a
multi-vulnerability advisory's severity and CWE were still attributed to whichever
single CVE the component carried - 23 assertions from advisories whose own titles say
"Multiple ... Vulnerabilities" and "Three weaknesses". Filing a five-fire news report
under one fire is not fixed by declining to open files for the other four. So:

* ALIAS CLAIM AND IDENTITY EQUIVALENCE ARE NOW TWO GRAPHS. Every alias assertion is
  recorded (alias_claims.jsonl.gz keeps the ones not admitted), but only claims from a
  record naming at most one CVE are unioned. Multi-CVE components drop from 4 to 0.
* ATTRIBUTION IS WITHHELD, NOT GUESSED. A record sitting in a claim cluster that names
  several CVEs, and naming none of them as its own id, keeps every assertion on its
  source record with entity_id=null and a stated reason. Its identity is untouched.
* record_role is decided by the record's OWN candidates. Using the component was the
  same "role from resolution" mistake one level down, and it mislabelled 20 records.
* sha256 actually performs the NFC its algorithm name promised, and "byte-identical
  rebuild" is now a test that builds twice and compares, not a sentence in a docstring.
"""
import argparse
import hashlib
import json
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Pure helpers with NO module-level side effects, so the acceptance gate can install
# its I/O spy before importing anything it audits. `build` is not among them and this
# module never imports build_unified_model.
REUSED_HELPERS = (
    'CANONICALIZATION', 'CANONICALIZATION_LEGACY', 'CVE_RE', 'GHSA_RE', 'TRANSFORM_RULES', 'entity_id_for',
    'extract_ghsa', 'extract_nvd', 'extract_osv', 'iter_jsonl_gz', 'obs', 'sha256_obj',
    'sha256_str', 'write_jsonl_gz',
)
from identity_extract import (
    CANONICALIZATION, CANONICALIZATION_LEGACY, CVE_RE, GHSA_RE, TRANSFORM_RULES, entity_id_for, extract_ghsa,
    extract_nvd, extract_osv, iter_jsonl_gz, obs, sha256_obj, sha256_str, write_jsonl_gz,
)

ROOT = Path(__file__).parent
DEFAULT_IN = ROOT / 'output' / 'h1_discovery'
DEFAULT_OUT = ROOT / 'output' / 'unified_model_v2'
V1_DIR = ROOT / 'output' / 'unified_model_v1'

# R13-F2: 2.2.0 covered two incompatible contracts (R11 and R12 both shipped under it).
# 2.3.0 = R12 field changes + R13 entity typing. Bump on every contract change; the
# gate asserts this exact value, so a change here without a gate update fails loudly.
MODEL_VERSION = '2.3.0-identity'
PROJECTION_VERSION = 'uvm-identity-projection-2'
# R11-F5: every .jsonl.gz section is byte-identical across rebuilds (the gate proves it
# by building twice and comparing). dataset_metadata.json is NOT - it carries
# generated_at_utc on purpose. This epoch is a frozen constant, not the build time.
DETERMINISTIC_EPOCH = 1784764800          # 2026-07-23T00:00:00Z

EXTRACTORS = {'nvd': extract_nvd, 'ghsa': extract_ghsa, 'osv': extract_osv}
SOURCES = ('nvd', 'ghsa', 'osv')

SECTIONS = ('identity_components', 'entities', 'identity_edges', 'alias_claims',
            'lineage_edges', 'source_records', 'entity_record_links',
            'assertions_severity', 'assertions_cwe', 'assertions_affected',
            'assertions_generic', 'transform_registry',
            'entities_cve_split_sensitivity')


# ---------------------------------------------------------------- identity rules
def identity_candidates(src, raw):
    """Every identifier the record ITSELF asserts about its own identity (spec s2).

    ALL alias shapes count, not only CVE-shaped ones: the OSV sample carries 2,156
    aliases split CVE 745 / GHSA 785 / other 626, and v1's CVE-only filter dropped
    1,411 of them.

    `upstream` and `related` are NOT here. They are lineage - where a fix came from,
    not who this record is - and they go to lineage_edges.

    Identifiers are trimmed and NFC-normalised; one real alias in the corpus
    ("U-3080225 ") carries a trailing space and would otherwise become a second,
    distinct node.
    """
    def clean(v):
        return unicodedata.normalize('NFC', v.strip()) if isinstance(v, str) else v

    if src == 'nvd':
        nid = clean((raw.get('cve') or {}).get('id'))
        return nid, ([{'id': nid, 'edge_type': 'native_id', 'basis': 'nvd_cve_id',
                       'original': (raw.get('cve') or {}).get('id')}] if nid else [])
    if src == 'ghsa':
        nid = clean(raw.get('ghsa_id'))
        out = [{'id': nid, 'edge_type': 'native_id', 'basis': 'ghsa_id',
                'original': raw.get('ghsa_id')}] if nid else []
        if raw.get('cve_id'):
            out.append({'id': clean(raw['cve_id']), 'edge_type': 'alias',
                        'basis': 'ghsa_cve_id', 'original': raw['cve_id']})
        for i in raw.get('identifiers') or []:
            if isinstance(i, dict) and i.get('value'):
                out.append({'id': clean(i['value']), 'edge_type': 'alias',
                            'basis': 'ghsa_identifiers', 'original': i['value']})
        return nid, out
    nid = clean(raw.get('id'))
    out = [{'id': nid, 'edge_type': 'native_id', 'basis': 'osv_id',
            'original': raw.get('id')}] if nid else []
    for a in raw.get('aliases') or []:
        out.append({'id': clean(a), 'edge_type': 'alias', 'basis': 'osv_aliases',
                    'original': a})
    return nid, out


def carried_cve(src, nid, raw, cand_ids, ambiguous=False):
    """The CVE this record designates as ITS OWN, or None.

    Round-9 policy D. "Someone mentioned this CVE id" and "we hold this CVE's record"
    are different facts, and only the second one earns an entity. A record that lists
    several CVEs and names none of them as its own is making a batch statement about an
    advisory, not an identity statement about itself.

    R12-F1: an ambiguous advisory carries NOTHING. GHSA-365w names exactly one cve_id, so
    the rule above would have it carry CVE-2026-56266 - but its own title says it covers
    five vulnerabilities. Letting it carry would also leave the component holding a
    carried CVE that is no longer one of its members, since the equivalence edge is gone.
    """
    if ambiguous:
        return None
    if nid and CVE_RE.match(nid):
        return nid                                    # the record IS that CVE
    if src == 'ghsa':
        c = (raw.get('cve_id') or '').strip()
        if c and CVE_RE.match(c):
            return c                                  # GHSA names its own CVE
    cves = [i for i in cand_ids if CVE_RE.match(i)]
    return cves[0] if len(cves) == 1 else None        # exactly one -> unambiguous


def record_role(n_upstream, has_related, record_has_own_cve):
    """Role comes from the record's OWN SHAPE, orthogonally to anything it resolved into.

    v1 asked "did the component lookup hit?" and therefore labelled everything it found
    `vulnerability_record`, leaving lineage_advisory and resolution_record at 0 forever.

    R11-F2: rounds 8-10 then used the record's COMPONENT to answer "does it have a CVE?",
    which is the same mistake one level down - 20 GHSA records with no CVE, no upstream
    and no related were labelled vulnerability_record purely because some OTHER record
    aliased them onto a CVE. The third argument is now the record's own identity
    candidates and nothing else.
    """
    if n_upstream >= 2:
        return 'bundle_advisory'          # >=2 upstream: one fix shipment, not one vuln
    if n_upstream == 1 and not record_has_own_cve:
        return 'lineage_advisory'
    if n_upstream == 0 and not has_related and not record_has_own_cve:
        return 'resolution_record'
    return 'vulnerability_record'


def record_is_ambiguous(in_multi_cve_claim_cluster, nid):
    """Does this record document a vulnerability we can name, or a batch we cannot?

    R12-F1. The round-11 rule only asked whether the record names >=2 CVEs itself. That
    let GHSA-365w-hqf6-vxfg through: it names exactly one cve_id, so its GHSA->CVE edge
    was identity-bearing and it took a primary link to CVE-2026-56266 - even though its
    own title reads "Crawl4AI: Multiple Docker API Vulnerabilities - File Write, SSRF,
    Auth Bypass, XSS, JS Execution". The assertions were withheld, but the advisory had
    still been stamped with one case's ID card, and coverage downstream would read that
    as exact coverage of that CVE.

    The structural evidence that a record belongs to a batch is that its CLAIM cluster
    holds several CVEs. A record whose own native id IS a CVE is exempt: NVD's record for
    CVE-2026-56266 is about that CVE whatever else is aliased around it.

    This is a STRUCTURAL signal, not a reading of the text. It answers "can this record's
    identity be pinned to one CVE?", never "how many vulnerabilities does it describe?" -
    see record_scope, which this build always reports as unknown.
    """
    return in_multi_cve_claim_cluster and not CVE_RE.match(nid or '')


def claim_is_equivalence_bearing(own_cve_count, ambiguous):
    """Is this record's alias list an identity assertion, or a batch statement?

    R11-F1. OSV's spec says `aliases` means "the same vulnerability", symmetric and
    transitive. This corpus does not honour that: PYSEC-2026-596 describes one SSRF and
    aliases five CVEs, five GHSAs and four sibling PYSEC records; GHSA-c9cv-mq2m-ppp3
    says "Three weaknesses" and carries three CVEs. Treating those as equivalence merges
    vulnerabilities the sources themselves describe as different.

    Both conditions must hold, and R12 learned the hard way that this is a CONJUNCTION
    rather than a replacement. Written as a replacement - ambiguous-only - the
    "native id is a CVE" exemption PROMOTES osv:CVE-2021-47987 (which names two CVEs) to
    equivalence-bearing and re-merges CVE-2021-47986 + CVE-2021-47987 + GHSA-593v into a
    single two-CVE component, undoing round 11. Component totals moved by just +1 while
    three splits and one merge cancelled out, so only a per-component diff caught it.
    """
    return own_cve_count <= 1 and not ambiguous


class UnionFind:
    def __init__(self):
        self.parent = {}

    def add(self, x):
        self.parent.setdefault(x, x)

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        """-> True if this call actually merged two distinct components."""
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        self.parent[ra] = rb
        return True


# ---------------------------------------------------------------- build
def build(input_dir, out_dir, quiet=False, stage='identity_validation'):
    assert stage in ('identity_validation', 'frozen'), stage
    input_dir, out_dir = Path(input_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    def say(*a):
        if not quiet:
            print(*a)

    say(f'[idv2] reading {input_dir} (identity-only, no presence matrix, no network)')

    # ---- pass 1: read, extract, collect identity candidates ----------------------
    records, failures = [], []
    uf = UnionFind()
    alias_disposition = Counter()
    trimmed = []
    for src in SOURCES:
        for raw in iter_jsonl_gz(input_dir / f'sample_{src}.jsonl.gz'):
            raw_sha = sha256_obj(raw)
            nid, cands = identity_candidates(src, raw)
            if not nid:
                failures.append({'source': src, 'raw_record_sha256': raw_sha,
                                 'reason': 'record carries no native identifier'})
                continue
            try:
                ex = EXTRACTORS[src](raw)
            except Exception as e:                       # never drop silently
                ex, err = None, f'{type(e).__name__}: {e}'
            else:
                err = None

            seen, ident = set(), []
            for c in cands:
                value = c['id']
                if not value:
                    continue
                if c['original'] != value:
                    trimmed.append({'source': src, 'record': f'{src}:{nid}',
                                    'original': c['original'], 'trimmed': value,
                                    'basis': c['basis']})
                if c['basis'] == 'osv_aliases':
                    if value == nid:
                        alias_disposition['self_reference'] += 1
                        continue
                    if value in seen:
                        alias_disposition['duplicate_noop'] += 1
                        continue
                elif (value == nid and c['edge_type'] != 'native_id') or value in seen:
                    continue
                seen.add(value)
                ident.append(c)
                uf.add(value)

            ids = [c['id'] for c in ident]
            own_cves = sorted({i for i in ids if CVE_RE.match(i)})
            records.append({
                'src': src, 'nid': nid, 'ref': f'{src}:{nid}', 'raw_sha': raw_sha,
                'ident': ident, 'ex': ex, 'error': err,
                'own_cves': own_cves, 'raw': raw,
                'upstream': [u.strip() for u in (raw.get('upstream') or [])
                             if isinstance(u, str)] if src == 'osv' else [],
                'related': [u.strip() for u in (raw.get('related') or [])
                            if isinstance(u, str)] if src == 'osv' else []})

    # ---- pass 2a: the CLAIM graph, and only then the scope decision ---------------
    # R12-F1: scope before equivalence. Whether a record's alias list may be unioned
    # depends on whether its identity can be pinned to one CVE, and THAT is only visible
    # once every claim in the corpus has been laid down. Deciding bearing during pass 1
    # is what let three multi-vulnerability advisories keep a CVE identity.
    claim_uf = UnionFind()
    for r in records:
        ids = [c['id'] for c in r['ident']]
        for i in ids:
            claim_uf.add(i)
        for i in ids[1:]:
            claim_uf.union(ids[0], i)
    claim_groups = defaultdict(set)
    for x in list(claim_uf.parent):
        claim_groups[claim_uf.find(x)].add(x)
    claim_cves = {root: sorted(x for x in mem if CVE_RE.match(x))
                  for root, mem in claim_groups.items()}
    for r in records:
        cluster = claim_cves[claim_uf.find(r['nid'])]
        r['claim_cluster_cves'] = cluster
        r['multi_cve_claim_cluster'] = len(cluster) > 1
        r['ambiguous'] = record_is_ambiguous(r['multi_cve_claim_cluster'], r['nid'])
        r['equivalence_bearing'] = claim_is_equivalence_bearing(len(r['own_cves']),
                                                               r['ambiguous'])
        r['carried'] = carried_cve(r['src'], r['nid'], r['raw'],
                                   [c['id'] for c in r['ident']], r['ambiguous'])

    # ---- pass 2b: the EQUIVALENCE graph ------------------------------------------
    identity_edges, alias_claims = [], []
    for r in records:
        ids = [c['id'] for c in r['ident']]
        for c in r['ident'][1:]:
            if r['equivalence_bearing']:
                merged = uf.union(ids[0], c['id'])
                if c['basis'] == 'osv_aliases':
                    alias_disposition['edge_created_new_link' if merged
                                      else 'edge_created_redundant'] += 1
                identity_edges.append({
                    'from_id': r['nid'], 'to_id': c['id'], 'source': r['src'],
                    'edge_type': c['edge_type'], 'edge_basis': c['basis'],
                    'original_value': c['original'], 'identity_bearing': True,
                    'strength': 'asserted_by_source', 'asserted_by': r['ref'],
                    'merged_components': merged})
            else:
                if c['basis'] == 'osv_aliases':
                    alias_disposition['claim_only_not_1to1'] += 1
                alias_claims.append({
                    'from_id': r['nid'], 'to_id': c['id'], 'source': r['src'],
                    'edge_type': c['edge_type'], 'edge_basis': c['basis'],
                    'original_value': c['original'], 'identity_bearing': False,
                    'claim_status': 'not_verified_1to1',
                    'claim_reason': (
                        f'the asserting record names {len(r["own_cves"])} distinct CVEs'
                        if len(r['own_cves']) > 1 else
                        f'the asserting record sits in a claim cluster naming '
                        f'{len(r["claim_cluster_cves"])} CVEs and names none of them as '
                        f'its own id, so its identity cannot be pinned to one of them'),
                    'asserted_by': r['ref'],
                    'asserting_record_cve_count': len(r['own_cves']),
                    'claim_cluster_cve_count': len(r['claim_cluster_cves'])})
        if r['equivalence_bearing'] and len(r['ident']) == 1:
            # a self edge keeps every record's own id present in the edge file, so the
            # identity-only path proof never falls back to another section
            identity_edges.append({
                'from_id': r['nid'], 'to_id': r['nid'], 'source': r['src'],
                'edge_type': 'native_id', 'edge_basis': r['ident'][0]['basis'],
                'original_value': r['ident'][0]['original'], 'identity_bearing': True,
                'strength': 'asserted_by_source', 'asserted_by': r['ref'],
                'merged_components': False})
        elif not r['equivalence_bearing']:
            # the batch record still needs its own id in the identity graph
            uf.add(r['nid'])
            identity_edges.append({
                'from_id': r['nid'], 'to_id': r['nid'], 'source': r['src'],
                'edge_type': 'native_id', 'edge_basis': r['ident'][0]['basis'],
                'original_value': r['ident'][0]['original'], 'identity_bearing': True,
                'strength': 'asserted_by_source', 'asserted_by': r['ref'],
                'merged_components': False})

    lineage_edges = [
        {'from_id': r['nid'], 'to_id': t, 'source': r['src'], 'edge_type': kind,
         'edge_basis': f'osv_{kind}', 'identity_bearing': False,
         'strength': 'asserted_by_source', 'asserted_by': r['ref']}
        for r in records
        for kind, targets in (('upstream', r['upstream']), ('related', r['related']))
        for t in targets]

    # ---- components --------------------------------------------------------------
    members = defaultdict(set)
    for x in list(uf.parent):
        members[uf.find(x)].add(x)
    recs_by_root = defaultdict(list)
    for r in records:
        recs_by_root[uf.find(r['nid'])].append(r)

    comp_of_id, comp_by_id = {}, {}
    for root, mem in members.items():
        mem_sorted = sorted(mem)
        rs = recs_by_root.get(root) or []
        # R9-F5: prefer an id a record actually calls its own. min(member_ids) once
        # anchored an entity on the alias MAL-2026-5274 instead of PYSEC-2026-581.
        natives = sorted({r['nid'] for r in rs} & mem)
        anchor = (natives or mem_sorted)[0]
        cid = 'IC-' + sha256_str(anchor)[:16]
        for m in mem_sorted:
            comp_of_id[m] = cid
        cves = sorted(x for x in mem_sorted if CVE_RE.match(x))
        carried = sorted({r['carried'] for r in rs if r['carried']})
        comp_by_id[cid] = {
            'component_id': cid, 'component_anchor': anchor,
            'component_anchor_is_source_native': bool(natives),
            'component_fingerprint': sha256_obj(mem_sorted),
            'member_ids': mem_sorted, 'member_id_count': len(mem_sorted),
            'cves': cves, 'cve_count': len(cves),
            'carried_cves': carried,
            'alias_only_cves': [c for c in cves if c not in carried],
            'ambiguity': 'no_cve' if not cves else 'single_cve' if len(cves) == 1
            else 'multi_cve',
            'member_record_refs': sorted(r['ref'] for r in rs),
            'has_records': bool(rs),
            'bundle_only': False, 'entity_ids': []}
    assert len({c['component_anchor'] for c in comp_by_id.values()}) == len(comp_by_id)

    # ---- claim clusters: evidence of batching, never identity ---------------------
    claim_members = claim_groups
    for cid, c in comp_by_id.items():
        roots = {claim_uf.find(m) for m in c['member_ids']}
        c['claim_cluster_ids'] = sorted('CC-' + sha256_str(min(claim_members[r]))[:16]
                                        for r in roots)
        c['claim_only_cve_ids'] = sorted({x for r in roots for x in claim_cves[r]}
                                         - set(c['cves']))

    # ---- roles (record-local shape ONLY) + advisory scope -------------------------
    for r in records:
        r['component_id'] = comp_of_id[r['nid']]
        # R11-F2: the record's OWN candidates, never its component
        r['role'] = record_role(len(r['upstream']), bool(r['related']),
                                bool(r['own_cves']))
        # R12-F2: three ORTHOGONAL facts, previously conflated into one field called
        # advisory_scope='multi_vulnerability'. Of the 36 assertions that label withheld,
        # only 23 have textual support (Crawl4AI "Multiple ... Vulnerabilities", Nuxt
        # "Three weaknesses"); the other 13 come from records whose own text describes a
        # SINGLE issue (OpenClaw's ZIP race, PYSEC-2026-596's SSRF). Calling those
        # multi_vulnerability asserted something the evidence does not support.
        #   multi_cve_claim_cluster - objective structure, computed from the claim graph
        #   record_scope            - a conclusion about the TEXT. This build performs no
        #                             text analysis and makes no manual determination, so
        #                             it is 'unknown' everywhere, by construction.
        #   attribution_status      - the handling decision that follows
        if r['ambiguous']:
            r['attribution_status'] = 'withheld_ambiguous'
            r['withheld_reason'] = (
                f'record sits in a claim cluster naming {len(r["claim_cluster_cves"])} '
                f'CVEs ({", ".join(r["claim_cluster_cves"])}) and names none of them as '
                'its own id, so its scope cannot be pinned to one vulnerability. It '
                'holds an identity of its own, but its assertions are attributed to NO '
                'entity and remain on this source record.')
        else:
            r['attribution_status'] = 'attributed'
            r['withheld_reason'] = None
        r['record_scope'] = 'unknown'      # no text analysis exists in this build
    role_counts = Counter(r['role'] for r in records)
    withheld_records = [r for r in records
                        if r['attribution_status'] == 'withheld_ambiguous']

    # A no-CVE component earns an entity unless every record in it is a bundle: one
    # RHSA is a shipment, not a vulnerability, and must not be issued an identity.
    recs_by_comp = defaultdict(list)
    for r in records:
        recs_by_comp[r['component_id']].append(r)
    for cid, c in comp_by_id.items():
        rs = recs_by_comp.get(cid) or []
        c['bundle_only'] = bool(rs) and all(x['role'] == 'bundle_advisory' for x in rs)

    # ---- entities: policy D ------------------------------------------------------
    # ONE entity per component that earns one. The invariant that makes this coherent
    # is that no component holds two carried CVEs; it is asserted, not assumed.
    multi_carrier = {cid: c['carried_cves'] for cid, c in comp_by_id.items()
                     if len(c['carried_cves']) > 1}
    if multi_carrier:
        raise SystemExit(
            'INVARIANT VIOLATED: components holding more than one carried CVE, so '
            '"one component one entity" cannot hold. Policy D needs revisiting for: '
            + json.dumps(dict(list(multi_carrier.items())[:5]), ensure_ascii=False))

    entities, entity_of_cve, entity_of_comp = [], {}, {}
    recordless_components = 0
    recs_by_cid = defaultdict(list)
    for r in records:
        recs_by_cid[r['component_id']].append(r)
    for cid in sorted(comp_by_id):
        c = comp_by_id[cid]
        if c['bundle_only']:
            continue
        if not c['has_records']:
            # ids we only ever saw mentioned in someone's alias list. We hold no record
            # for them, so there is nothing to issue an identity to (spec s3's rule for
            # referenced-only CVEs, applied to every identifier shape).
            recordless_components += 1
            continue
        if c['carried_cves']:
            anchor, kind = c['carried_cves'][0], 'cve'
        else:
            anchor, kind = c['component_anchor'], 'no_cve_component'
        # R13-F1: an entity for an advisory whose scope cannot be pinned to one CVE is a
        # different KIND of thing from a canonical vulnerability identity, and a reader
        # of entities.jsonl.gz must be able to tell without joining source_records. The
        # folder is numbered; this is the label saying whether it is a case file or a
        # binder of advisories. Structurally these components hold ONLY withheld
        # records, so any/all agree - the gate asserts that.
        member_recs = recs_by_cid[cid]
        ambiguous_all = bool(member_recs) and all(
            r['attribution_status'] == 'withheld_ambiguous' for r in member_recs)
        ambiguous_any = any(
            r['attribution_status'] == 'withheld_ambiguous' for r in member_recs)
        assert ambiguous_all == ambiguous_any,             f'{cid}: mixed attribution inside one component'
        entity_kind = 'ambiguous_advisory' if ambiguous_all else 'canonical_identity'
        eid = entity_id_for(anchor)
        c['entity_ids'].append(eid)
        if kind == 'cve':
            entity_of_cve[anchor] = eid
        entity_of_comp[cid] = eid
        entities.append({
            'entity_id': eid, 'preferred_identifier': anchor, 'anchor_kind': kind,
            'anchor_id': anchor, 'component_id': cid,
            'entity_kind': entity_kind,
            'vulnerability_analysis_eligible': entity_kind == 'canonical_identity',
            'cve_ids': c['cves'], 'carried_cve_ids': c['carried_cves'],
            'alias_only_cve_ids': c['alias_only_cves'],
            'multi_cve_alias': c['cve_count'] > 1,
            'component_ambiguity': c['ambiguity'],
            'member_id_count': c['member_id_count']})
    entity_by_id = {e['entity_id']: e for e in entities}
    assert len(entity_by_id) == len(entities), 'entity_id collision'
    say(f'[idv2] components {len(comp_by_id):,} (claim {len(claim_members):,}, '
        f'record-less {recordless_components:,})  entities {len(entities):,} '
        f'(CVE-anchored {len(entity_of_cve):,}, no-CVE '
        f'{sum(1 for e in entities if e["anchor_kind"] == "no_cve_component"):,})')
    say(f'[idv2] roles {dict(role_counts)}')
    say(f'[idv2] alias claims not admitted as equivalence: {len(alias_claims):,}; '
        f'records with attribution withheld: {len(withheld_records):,}')

    # ---- identity-only path proofs -----------------------------------------------
    adj = defaultdict(list)
    for i, e in enumerate(identity_edges):
        if e['from_id'] == e['to_id']:
            continue
        adj[e['from_id']].append((e['to_id'], i))
        adj[e['to_id']].append((e['from_id'], i))

    def identity_path(start, goal):
        """BFS over identity-bearing edges ONLY. Returns the edge hops, or None."""
        if start == goal:
            return []
        seen, queue = {start}, [(start, [])]
        while queue:
            nxt = []
            for node, path in queue:
                for peer, ei in adj.get(node, ()):
                    if peer in seen:
                        continue
                    e = identity_edges[ei]
                    hop = path + [{'from_id': e['from_id'], 'to_id': e['to_id'],
                                   'edge_type': e['edge_type'],
                                   'edge_basis': e['edge_basis'], 'source': e['source']}]
                    if peer == goal:
                        return hop
                    seen.add(peer)
                    nxt.append((peer, hop))
            queue = nxt
        return None

    # ---- resolution of a referenced identifier -----------------------------------
    def resolve(rid):
        """-> (entity_id|None, resolution, component_id|None)

        Every component holds at most one entity (asserted above), so a reference can
        never fan out. What still needs care is a reference to a CVE that no record
        carries: it belongs to a vulnerability we never received, so it must NOT be
        attached to whichever entity happens to share its component.
        """
        cid = comp_of_id.get(rid)
        if CVE_RE.match(rid) and rid not in entity_of_cve:
            return None, 'referenced_only_cve', cid
        if cid is None:
            return None, ('outside_cohort' if GHSA_RE.match(rid) else 'unresolved'), None
        if rid in entity_of_cve:
            return entity_of_cve[rid], 'resolved_in_cohort', cid
        eid = entity_of_comp.get(cid)
        if eid is None:
            return None, 'resolved_no_entity_by_policy', cid   # bundle-only component
        return eid, 'resolved_in_cohort', cid

    # ---- source records, links, assertions ---------------------------------------
    source_records, links, link_keys = [], [], {}
    sev_a, cwe_a, aff_a, gen_a = [], [], [], []
    status_counts, primary_linked = Counter(), set()
    exact_dupes = Counter()

    def add_link(row):
        """R9-F2: the key is the full relation, not just the pair.

        Deduplicating on (record_ref, referenced_id) alone silently dropped 4,961
        distinct relations - 4,702 targets a record asserted as BOTH upstream and
        related, and 259 lineage targets that collided with its own primary link. Those
        are different statements about the same pair and all of them are kept.
        """
        key = (row['record_ref'], row['referenced_id'], row['link_role'],
               row['link_basis'])
        if key in link_keys:
            exact_dupes[row['link_basis']] += 1     # same relation asserted twice
            return
        link_keys[key] = len(links)
        links.append(row)

    for r in records:
        ref, nid, src = r['ref'], r['nid'], r['src']
        cid = r['component_id']
        comp = comp_by_id[cid]
        warns = []

        if r['error'] is not None:
            source_records.append({
                'record_ref': ref, 'source': src, 'native_id': nid,
                'component_id': cid, 'record_role': r['role'],
                'multi_cve_claim_cluster': r['multi_cve_claim_cluster'],
                'record_scope': r['record_scope'],
                'attribution_status': r['attribution_status'],
                'attribution_withheld_reason': r['withheld_reason'],
                'claim_cluster_cve_ids': r['claim_cluster_cves'],
                'own_cve_ids': r['own_cves'],
                'alias_claims_are_equivalence_bearing': r['equivalence_bearing'],
                'conversion_status': 'failed', 'failure_reason': r['error'],
                'warnings': [], 'entity_id': None, 'entity_binding': 'not_attempted',
                'carried_cve': r['carried'], 'identity_path_length': None,
                'raw_record_sha256': r['raw_sha'], 'temporal': None})
            status_counts['failed'] += 1
            continue
        ex = r['ex']

        if r['role'] == 'bundle_advisory':
            eid, binding = None, 'no_entity_by_policy'
            warns.append('bundle advisory (>=2 upstream): a fix shipment, not a '
                         'vulnerability. No entity; assertions stay on this record.')
        elif r['carried']:
            eid, binding = entity_of_cve[r['carried']], 'carried_cve'
        elif comp['carried_cves']:
            eid, binding = entity_of_cve[comp['carried_cves'][0]], 'component_carried_cve'
            if comp['cve_count'] > 1:
                warns.append(
                    f'record names {comp["cve_count"]} CVEs and none as its own id; '
                    f'bound to {comp["carried_cves"][0]}, the only one any record in '
                    f'this component carries. The others '
                    f'({", ".join(comp["alias_only_cves"])}) are alias-mentioned only '
                    'and hold no entity.')
        elif cid in entity_of_comp:
            eid, binding = entity_of_comp[cid], 'component_anchor'
        else:
            eid, binding = None, 'no_entity_by_policy'
            warns.append('no CVE identity and the component carries only bundle '
                         'advisories; no entity issued')

        if not (ex['severities'] or ex['cwes'] or ex['affected'] or ex['texts']):
            warns.append('record carries no field the model currently models; it '
                         'contributes no assertion')

        path = None
        if eid is not None:
            anchor = entity_by_id[eid]['anchor_id']
            path = identity_path(nid, anchor)
            if path is None:
                warns.append('INTERNAL: no identity-only path to the anchor')
            else:
                primary_linked.add(ref)
                add_link({'record_ref': ref, 'entity_id': eid, 'referenced_id': nid,
                          'component_id': cid, 'link_role': 'primary_record',
                          'link_basis': 'native_id', 'resolution': 'resolved_in_cohort',
                          'identity_path': path, 'identity_path_length': len(path)})

        # every lineage reference gets its own row, resolved or not. A reference that
        # lands nowhere is recorded as such: never invented, never dropped.
        for kind, targets in (('upstream', r['upstream']), ('related', r['related'])):
            for t in targets:
                t_eid, resolution, t_cid = resolve(t)
                add_link({'record_ref': ref, 'entity_id': t_eid, 'referenced_id': t,
                          'component_id': t_cid, 'link_role': 'resolution_only',
                          'link_basis': kind, 'resolution': resolution,
                          'identity_path': None, 'identity_path_length': None})

        if r['attribution_status'] == 'withheld_ambiguous':
            warns.append(r['withheld_reason'])

        source_records.append({
            'record_ref': ref, 'source': src, 'native_id': nid, 'component_id': cid,
            'record_role': r['role'],
            'multi_cve_claim_cluster': r['multi_cve_claim_cluster'],
            'record_scope': r['record_scope'],
            'attribution_status': r['attribution_status'],
            'attribution_withheld_reason': r['withheld_reason'],
            'claim_cluster_cve_ids': r['claim_cluster_cves'],
            'own_cve_ids': r['own_cves'],
            'alias_claims_are_equivalence_bearing': r['equivalence_bearing'],
            'conversion_status': 'converted_with_warnings' if warns else 'converted',
            'failure_reason': None, 'warnings': warns,
            'entity_id': eid, 'entity_binding': binding, 'carried_cve': r['carried'],
            'identity_path_length': None if path is None else len(path),
            'raw_record_sha256': r['raw_sha'],
            'temporal': {'source_published_at': ex.get('published'),
                         'source_modified_at': ex.get('modified'),
                         'content_sha256': r['raw_sha'],
                         'projection_version': PROJECTION_VERSION,
                         'canonicalization_algorithm': CANONICALIZATION}})
        status_counts[source_records[-1]['conversion_status']] += 1

        # ONE row per extracted item. v1 looped `for eid in (targets or [None])` and
        # duplicated every assertion once per bound entity; entity_id is a nullable
        # LINK here, and source_record_ref is the key.
        # R11-F1: a multi-vulnerability advisory's severity/CWE/affected describe
        # SEVERAL vulnerabilities. They are kept in full, anchored on the source record,
        # but attributed to no entity - hanging them on whichever CVE happens to be
        # carried is how a five-fire news report ends up filed under one fire.
        assertion_entity = None if r['attribution_status'] == 'withheld_ambiguous' else eid
        common = {'source_record_ref': ref, 'entity_id': assertion_entity,
                  'record_role': r['role'], 'entity_binding': binding,
                  'multi_cve_claim_cluster': r['multi_cve_claim_cluster'],
                  'record_scope': r['record_scope'],
                  'attribution_status': r['attribution_status'],
                  'attribution_withheld_reason': r['withheld_reason']}
        for s in ex['severities']:
            sev_a.append({**common, 'scale': s['scale'], 'score': s['score'],
                          'vector': s['vector'], 'label': s['label'],
                          'observations': [obs(src, ref, nid, s['pointer'], r['raw_sha'],
                                               s['original'], s['status'], s['rule'],
                                               ex.get('modified'))]})
        for c in ex['cwes']:
            cwe_a.append({**common, 'value': c['value'], 'is_sentinel': c['is_sentinel'],
                          'observations': [obs(src, ref, nid, c['pointer'], r['raw_sha'],
                                               c['original'], c['status'], c['rule'],
                                               ex.get('modified'))]})
        for a in ex['affected']:
            aff_a.append({**common, 'package_name': a['package_name'],
                          'ecosystem': a['ecosystem'], 'purl': a['purl'], 'cpe': a['cpe'],
                          'ranges': a['ranges'],
                          'first_patched_version': a['first_patched_version'],
                          'remediation_kind': a['remediation_kind'],
                          'proxy_derived_from': a['proxy_derived_from'],
                          'observations': [obs(src, ref, nid, a['pointer'], r['raw_sha'],
                                               a['original'], a['status'], a['rule'],
                                               ex.get('modified'))]})
        for t in ex['texts']:
            gen_a.append({**common, 'field': t['field'], 'value': t['value'],
                          'observations': [obs(src, ref, nid, t['pointer'], r['raw_sha'],
                                               t['original'], t['status'], t['rule'],
                                               ex.get('modified'))]})

    for f in failures:
        ref = f'{f["source"]}:<missing-id>'
        source_records.append({
            'record_ref': ref, 'source': f['source'], 'native_id': '<missing>',
            'component_id': None, 'record_role': 'resolution_record',
            'multi_cve_claim_cluster': False, 'record_scope': 'unknown',
            'attribution_status': 'attributed',
            'attribution_withheld_reason': None, 'claim_cluster_cve_ids': [],
            'own_cve_ids': [],
            'alias_claims_are_equivalence_bearing': True,
            'conversion_status': 'failed', 'failure_reason': f['reason'], 'warnings': [],
            'entity_id': None, 'entity_binding': 'not_attempted', 'carried_cve': None,
            'identity_path_length': None,
            'raw_record_sha256': f['raw_record_sha256'], 'temporal': None})
        status_counts['failed'] += 1

    # ---- CVE-split sensitivity (the rejected policy, kept for comparison) ---------
    split = []
    for cid in sorted(comp_by_id):
        c = comp_by_id[cid]
        if c['bundle_only']:
            continue
        if c['cves']:
            for cve in c['cves']:
                split.append({'entity_id': entity_id_for(cve), 'anchor_id': cve,
                              'anchor_kind': 'cve', 'component_id': cid,
                              'has_carrier_record': cve in c['carried_cves']})
        else:
            split.append({'entity_id': entity_id_for(c['component_anchor']),
                          'anchor_id': c['component_anchor'],
                          'anchor_kind': 'no_cve_component', 'component_id': cid,
                          'has_carrier_record': True})

    say(f'[idv2] source records {len(source_records):,} {dict(status_counts)}')
    say(f'[idv2] identity edges {len(identity_edges):,}  lineage edges '
        f'{len(lineage_edges):,}  links {len(links):,} '
        f'(exact duplicate relations collapsed: {sum(exact_dupes.values()):,})')
    say(f'[idv2] assertions severity {len(sev_a):,} cwe {len(cwe_a):,} '
        f'affected {len(aff_a):,} generic {len(gen_a):,}')

    # ---- write --------------------------------------------------------------------
    for c in comp_by_id.values():
        c['entity_ids'].sort()
    sections = {
        'identity_components': [comp_by_id[k] for k in sorted(comp_by_id)],
        'entities': entities,
        'identity_edges': identity_edges,
        'alias_claims': alias_claims,
        'lineage_edges': lineage_edges,
        'source_records': source_records,
        'entity_record_links': links,
        'assertions_severity': sev_a, 'assertions_cwe': cwe_a,
        'assertions_affected': aff_a, 'assertions_generic': gen_a,
        'transform_registry': [{'rule_id': r_, 'class': c_, 'description': d_,
                                'invertible': i_, 'applies_to': a_}
                               for r_, c_, d_, i_, a_ in TRANSFORM_RULES],
        'entities_cve_split_sensitivity': split,
    }
    assert set(sections) == set(SECTIONS), 'SECTIONS is out of sync with the writer'
    for name, rows in sections.items():
        write_jsonl_gz(out_dir / f'{name}.jsonl.gz', rows)

    inputs = {}
    for s in SOURCES:
        p = input_dir / f'sample_{s}.jsonl.gz'
        h = hashlib.sha256()
        with open(p, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b''):
                h.update(chunk)
        inputs[p.name] = h.hexdigest()
    meta = {
        'model_version': MODEL_VERSION,
        'layer': ('identity-only. Spec IDENTITY_LAYER_V2_SPEC.md, plus round-9 policy D '
                  '(an entity only for a CVE some record carries), round-11 claim vs '
                  'equivalence split, and round-12 scope-before-equivalence: a record '
                  'whose claim cluster names several CVEs and which names none of them '
                  'as its own id gets NO CVE identity.'),
        'build_stage': stage,
        'report_eligible': stage == 'frozen',
        'deterministic_build_epoch_utc':
            datetime.fromtimestamp(DETERMINISTIC_EPOCH, tz=timezone.utc).isoformat(),
        'deterministic_build_epoch': DETERMINISTIC_EPOCH,
        'generated_at_utc': datetime.now(timezone.utc).isoformat(),
        'built_at_note': ('deterministic_build_epoch_utc is a FROZEN constant, not a '
                          'build time. Every .jsonl.gz section IS byte-identical across '
                          'rebuilds (the gate proves it by building twice); '
                          'dataset_metadata.json is NOT, because generated_at_utc holds '
                          'the real wall-clock time this build ran.'),
        'input_dir': str(input_dir), 'inputs': inputs,
        'entity_policy': (
            'Policy D (round 9). One entity per component that earns one. A CVE earns '
            'an entity only when a record CARRIES it (own native id / GHSA cve_id / the '
            'single CVE among its aliases); a CVE that is merely alias-mentioned holds '
            'no entity, exactly like a bundle-referenced CVE. Bundle advisories get no '
            'entity. This supersedes spec section 3, which said to split every '
            'multi-CVE component - that produced entities no record claims, while '
            'merging by alias closure would have merged demonstrably distinct '
            'vulnerabilities batched into one advisory.'),
        'identity_policy': (
            'TWO graphs. The claim graph records every alias assertion any record makes '
            '(source-native id, all alias shapes, GHSA identifiers[].value and cve_id, '
            'trimmed and NFC-normalised) and is evidence only. The equivalence graph is '
            'the sole input to the union and admits a claim only when the asserting '
            'record names at most one CVE AND is not ambiguous - ambiguous meaning its '
            'claim cluster names several CVEs while its own native id is not one of '
            'them. Claims not admitted are kept in alias_claims.jsonl.gz. upstream and '
            'related are lineage and never enter either identity decision.'),
        'id_stability': (
            'entity_id and component_id are DETERMINISTIC for a given member set, '
            'derived from a source-issued anchor that prefers an id some record calls '
            'its own. They are NOT guaranteed stable across snapshots: a new member '
            'sorting ahead of the current anchor changes the anchor. Cross-snapshot '
            'stability would need a persisted anchor registry, which this build does '
            'not have.'),
        'cohort': {'seed_records': len(source_records),
                   'entities_total': len(entities),
                   'ambiguous_advisory_entities': sum(
                       1 for e in entities if e['entity_kind'] == 'ambiguous_advisory'),
                   'vulnerability_metric_eligible': sum(
                       1 for e in entities if e['vulnerability_analysis_eligible']),
                   'primary_linked_records': len(primary_linked),
                   'identity_components': len(comp_by_id), 'entities': len(entities),
                   'carried_cves': len(entity_of_cve),
                   'alias_only_cves': sum(len(c['alias_only_cves'])
                                          for c in comp_by_id.values()),
                   'recordless_components': recordless_components,
                   'alias_claims_not_admitted': len(alias_claims),
                   'attribution_withheld_records': len(withheld_records),
                   'record_roles': dict(sorted(role_counts.items()))},
        'counts': {k: len(v) for k, v in sections.items()},
    }
    (out_dir / 'dataset_metadata.json').write_text(
        json.dumps(meta, indent=1, ensure_ascii=False, sort_keys=True), encoding='utf-8')

    say(f'[idv2] wrote {len(sections)} sections + dataset_metadata.json to {out_dir}')
    return {'records': records, 'comp_by_id': comp_by_id, 'entities': entities,
            'role_counts': role_counts, 'alias_disposition': alias_disposition,
            'links': links, 'sections': sections, 'meta': meta, 'trimmed': trimmed,
            'exact_dupes': exact_dupes, 'entity_by_id': entity_by_id,
            'entity_of_cve': entity_of_cve, 'split': split,
            'recordless_components': recordless_components,
            'alias_claims': alias_claims, 'withheld_records': withheld_records,
            'claim_members': claim_members}


# ---------------------------------------------------------------- audit report
def v1_comparison():
    """v1 numbers recomputed from the v1 build, for the audit report ONLY.

    A reporting call made after the model is written. It reads v1's OUTPUT, never the
    id_to_component lookup table v1 resolved through.
    """
    try:
        comps = list(iter_jsonl_gz(V1_DIR / 'identity_components.jsonl.gz'))
        ents = list(iter_jsonl_gz(V1_DIR / 'entities.jsonl.gz'))
    except OSError:
        return None
    amb = Counter(c['ambiguity'] for c in comps)
    anchors = Counter(e['anchor_kind'] for e in ents)
    return {'identity_components': len(comps),
            'max_component_member_ids': max(c['member_id_count'] for c in comps),
            'multi_cve_components': amb.get('multi_cve', 0),
            'no_cve_components': amb.get('no_cve', 0),
            'entities': len(ents),
            'cve_anchored_entities': anchors.get('cve', 0),
            'no_cve_anchored_entities': anchors.get('no_cve_component', 0),
            'note': ('v1 is known_bad_superseded. Its CVE anchor count is HIGHER than '
                     'v2 because the old component table unioned upstream, so CVEs only '
                     'ever referenced by a bundle became anchors of their own.')}


def audit_report(stats, out_dir, input_dir, compare_v1=True,
                 stage='identity_validation'):
    comp_by_id, records = stats['comp_by_id'], stats['records']
    amb = Counter(c['ambiguity'] for c in comp_by_id.values())
    role_samples = defaultdict(list)
    for r in records:
        role_samples[r['role']].append(
            {'record_ref': r['ref'], 'component_id': r['component_id'],
             'upstream_count': len(r['upstream']), 'related_count': len(r['related']),
             'component_cve_count': comp_by_id[r['component_id']]['cve_count']})

    prim = [l for l in stats['links'] if l['link_role'] == 'primary_record']
    prim.sort(key=lambda l: -(l['identity_path_length'] or 0))
    hop_hist = Counter(l['identity_path_length'] for l in prim)
    resolutions = Counter(l['resolution'] for l in stats['links']
                          if l['link_role'] == 'resolution_only')

    multi = [c for c in comp_by_id.values() if c['cve_count'] > 1]
    v2 = {'identity_components': len(comp_by_id),
          'max_component_member_ids': max(c['member_id_count']
                                          for c in comp_by_id.values()),
          'multi_cve_components': amb.get('multi_cve', 0),
          'no_cve_components': amb.get('no_cve', 0),
          'entities': len(stats['entities']),
          'cve_anchored_entities': sum(1 for e in stats['entities']
                                       if e['anchor_kind'] == 'cve'),
          'no_cve_anchored_entities': sum(1 for e in stats['entities']
                                          if e['anchor_kind'] == 'no_cve_component')}

    report = {
        'report': 'identity layer v2 audit',
        'spec': 'schemas/IDENTITY_LAYER_V2_SPEC.md + round-9 policy D',
        # R14-F1: this used to be hardcoded to identity_validation/False, so a
        # `--stage frozen` build produced a box stamped APPROVED containing a
        # certificate reading NOT YET APPROVED - and no check compared the two.
        # The stage now comes from the build; report_eligible additionally requires a
        # PASSING gate, which only --write-audit can establish.
        'build_stage': stage, 'report_eligible': False,
        'report_eligible_note': ('false until Test_identity_acceptance.py --write-audit '
                                 'records a passing run at this exact source; a frozen '
                                 'build_stage alone never makes a report quotable'),
        'input_dir': str(input_dir), 'generated_for': str(out_dir),
        'acceptance_conditions': {
            'status': 'not_evaluated - run Test_identity_acceptance.py --write-audit'},
        'entity_policy': {
            'rule': ('Policy D + round-11 claim/equivalence split. A CVE earns an entity '
                     'only when some record CARRIES it (own native id / GHSA cve_id / '
                     'the single CVE among its aliases). Ids we only ever saw mentioned '
                     'get no entity, and neither does a component holding no record at '
                     'all - the referenced-only rule of spec section 3, applied to '
                     'every identifier shape.'),
            'entities': len(stats['entities']),
            'recordless_components_without_an_entity': stats['recordless_components'],
            'alias_only_cves_without_an_entity': sum(
                len(c['alias_only_cves']) for c in comp_by_id.values()),
            'entity_count_by_policy': {
                'alias_closure_split_per_cve': len(stats['split']),
                'verified_equivalence_policy_D': len(stats['entities'])},
        },
        'claim_vs_equivalence': {
            'why': ('R11-F1. OSV specifies aliases as same-vulnerability, symmetric and '
                    'transitive. This corpus does not honour that, so alias claims are '
                    'recorded as EVIDENCE and only verified-1:1 claims are unioned.'),
            'rule': ('a claim is admitted to the union only when the asserting record '
                     'names at most one CVE AND is not ambiguous. Ambiguous = its claim '
                     'cluster names several CVEs while its own native id is not one of '
                     'them. R12 note: this is a CONJUNCTION - written as a replacement, '
                     'the native-id exemption re-merges CVE-2021-47986 with '
                     'CVE-2021-47987, and component totals move by only +1 because three '
                     'splits and one merge cancel out.'),
            'record_scope_note': (
                'record_scope is a conclusion about the TEXT and is reported as '
                '"unknown" for every record: this build performs no text analysis and '
                'makes no manual determination. multi_cve_claim_cluster carries the '
                'structural fact instead.'),
            'manual_scope_review': {
                'note': ('A MANUAL scope reading done in round 12, recorded HERE ONLY '
                         'as situational commentary - deliberately not encoded in the '
                         'data, and NOT a completed sensitivity analysis. Of the 36 '
                         'withheld assertions, 23 come from records whose own text '
                         'describes several vulnerabilities and 13 from records whose '
                         'text describes one. Withholding all 36 is the conservative '
                         'choice while record_scope is unknown.'),
                'text_says_several': {'ghsa:GHSA-365w-hqf6-vxfg': 10,
                                      'ghsa:GHSA-c9cv-mq2m-ppp3': 7,
                                      'osv:GHSA-c9cv-mq2m-ppp3': 6},
                'text_says_one': {'ghsa:GHSA-r54r-wmmq-mh84': 6,
                                  'osv:GHSA-r54r-wmmq-mh84': 5,
                                  'osv:PYSEC-2026-596': 2}},
            'claim_components': len(stats['claim_members']),
            'equivalence_components': len(comp_by_id),
            'equivalence_components_holding_more_than_one_cve': amb.get('multi_cve', 0),
            'alias_claims_not_admitted': len(stats['alias_claims']),
            'records_making_batch_claims': sorted(
                {c['asserted_by'] for c in stats['alias_claims']}),
            'attribution': {
                'rule': ('a record whose claim cluster names >=2 CVEs, and whose own '
                         'native id is not one of them, CANNOT BE RELIABLY PINNED to a '
                         'single CVE. Whether it actually documents several '
                         'vulnerabilities is a text question this build does not answer '
                         '(record_scope=unknown). Its assertions are kept in full on '
                         'the source record and attributed to NO entity.'),
                'records': [
                    {'record_ref': r['ref'], 'own_cve_ids': r['own_cves'],
                     'reason': r['withheld_reason']} for r in stats['withheld_records']],
                'record_count': len(stats['withheld_records'])},
            'manual_adjudication': (
                'All four multi-CVE claim clusters were inspected by hand. Crawl4AI '
                '(GHSA-365w: "Multiple Docker API Vulnerabilities - File Write, SSRF, '
                'Auth Bypass, XSS, JS Execution") and Nuxt (GHSA-c9cv: "Three '
                'weaknesses") demonstrably alias DISTINCT vulnerabilities batched into '
                'one advisory. OpenClaw and Parse Server look like duplicate CVE '
                'assignment for one bug. The rule handles all four the same way: the '
                'claim is recorded, the union is not made, and assertions from records '
                'that name no CVE of their own are not attributed.'),
        },
        'v1_v2_comparison': {'v1': v1_comparison() if compare_v1 else None, 'v2': v2},
        'relation_conservation': {
            'key': '(record_ref, referenced_id, link_role, link_basis)',
            'link_rows': len(stats['links']),
            'primary': len(prim),
            'resolution_only': len(stats['links']) - len(prim),
            'exact_duplicate_relations_collapsed': dict(sorted(
                stats['exact_dupes'].items())),
            'note': ('R9-F2: the previous 2-key dedup dropped 4,961 distinct relations '
                     'without saying so. Only byte-identical repeats of the SAME '
                     'relation are collapsed now, and they are counted above.')},
        'alias_disposition': {
            'scope': 'OSV aliases[] occurrences in the input',
            'total': sum(stats['alias_disposition'].values()),
            'breakdown': dict(sorted(stats['alias_disposition'].items()))},
        'identifier_hygiene': {
            'trimmed_identifiers': len(stats['trimmed']), 'examples': stats['trimmed'][:5],
            'note': 'original_value is preserved on every identity edge'},
        'record_roles': {'counts': dict(sorted(stats['role_counts'].items())),
                         'samples': {k: v[:3] for k, v in sorted(role_samples.items())}},
        'entity_binding': dict(sorted(Counter(
            r['entity_binding'] for r in stats['sections']['source_records']).items())),
        'reference_resolution': dict(sorted(resolutions.items())),
        'identity_path_proofs': {
            'primary_links': len(prim),
            'hops_histogram': {str(k): v for k, v in sorted(hop_hist.items())},
            'note': ('0 hops means the record\'s own native id IS the entity anchor. '
                     'Samples are the longest chains plus two 0-hop cases; every hop is '
                     'an identity-bearing edge.'),
            'samples': [{'record_ref': l['record_ref'], 'entity_id': l['entity_id'],
                         'anchor_id': stats['entity_by_id'][l['entity_id']]['anchor_id'],
                         'hops': l['identity_path_length'],
                         'identity_path': l['identity_path']}
                        for l in prim[:8] + prim[-2:]]},
        'id_stability': stats['meta']['id_stability'],
        'canonicalization': {
            'algorithm': CANONICALIZATION,
            'superseded': CANONICALIZATION_LEGACY,
            'note': ('R12-F3: -nfc-1 named an NFC step that no code performed. NFC is '
                     'applied from round 11 on, which changes raw_record_sha256 for the '
                     '11 records in the corpus containing non-NFC strings, so the '
                     'algorithm name was bumped rather than silently reused.')},
        'known_spec_discrepancies': [
            {'spec_section': '3',
             'claim': 'referenced-only CVEs = 2,507',
             'measured': ('CVEs in bundle upstream never observed as a record identity '
                          '= 3,888 (3,400 strictly bundle-only); all-upstream = 5,080. '
                          'The closest match to 2,507 is a different quantity: CVEs in '
                          '`related` never observed = 2,498.'),
             'impact': 'none on the model; reported as measured, 2,507 is not asserted'},
            {'spec_section': '3 / 6.4',
             'claim': 'multi-CVE components must be SPLIT into one entity per CVE, each '
                      'merge_blocked',
             'measured': ('splitting produced 8 entities that no record claims as a '
                          'primary; merging by alias closure would merge demonstrably '
                          'distinct vulnerabilities'),
             'impact': 'SUPERSEDED by round-9 policy D; merge_blocked is retired'},
        ],
    }
    (out_dir / 'identity_audit_report.json').write_text(
        json.dumps(report, indent=1, ensure_ascii=False, sort_keys=True), encoding='utf-8')
    return report


def main():
    ap = argparse.ArgumentParser(description='identity layer v2 builder (identity-only)')
    ap.add_argument('--input-dir', default=str(DEFAULT_IN))
    ap.add_argument('--out-dir', default=str(DEFAULT_OUT))
    ap.add_argument('--no-audit', action='store_true',
                    help='skip the audit report (used by the runtime file-read probe)')
    ap.add_argument('--no-v1-compare', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--stage', choices=('identity_validation', 'frozen'),
                    default='identity_validation',
                    help=('frozen stamps build_stage=frozen / report_eligible=true. '
                          'Only used after every gate has passed at this exact source; '
                          'the freeze decision itself belongs to the reviewer.'))
    args = ap.parse_args()

    if Path(args.out_dir).resolve() == V1_DIR.resolve():
        sys.exit('refusing to write into the v1 model directory')
    stats = build(args.input_dir, args.out_dir, quiet=args.quiet, stage=args.stage)
    if not args.no_audit:
        audit_report(stats, Path(args.out_dir), Path(args.input_dir),
                     compare_v1=not args.no_v1_compare, stage=args.stage)
        if not args.quiet:
            print('[idv2] wrote identity_audit_report.json')
    return stats


if __name__ == '__main__':
    main()
