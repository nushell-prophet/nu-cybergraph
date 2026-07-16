# nu-cybergraph

A local cybergraph on a git backend: content-addressed link records between particles (files), with per-link authorship and birth-time proofs built on [nu-multiproof](https://codeberg.org/nushell-prophet/nu-multiproof/).

🚧 Proof of concept, agent-written, barely tested — do not treat as secure. The concept it implements is developed in the `bostrom-journal` (bj003).

## Concept

A **particle** is any content-addressed file (CID v0). A **link** is a directed edge between two particles, asserted by a **neuron** — an identity that is itself just the CID of an SSH public key. A neuron's cybergraph is a git repository of link records.

The design goal is cheap per-link portability: one neuron can hand a single link to another with a verifiable author signature and a verifiable birth-time bound, **without** signing every record individually and without shipping its whole graph. The mechanism is a **birth certificate**: sign and OTS-stamp one merkle root per seal (nu-multiproof's machinery), then freeze each link's inclusion proof from the first seal that catalogued it.

## Quick start

```nushell no-run
use nu-cybergraph/

nu-cybergraph init                       # multiproof init + links/ certs/ under <repo>/cybergraph/
nu-cybergraph link add Qm…from Qm…to     # write links/<cid>.json
nu-cybergraph seal                       # sign + stamp the root, freeze new certificates
nu-cybergraph bundle Qm…link             # portable bundle → exports/<cid>/
nu-cybergraph import path/to/bundle      # verify, then keep under imported/<neuron>/<cid>/
nu-cybergraph verify Qm…link             # own or imported, always against the birth seal
```

## Link record format

Pinned exactly (reference: `nu-cybergraph/_record.nu`; golden bytes and CID: `tests/test_record.nu`), so an independent implementation reproduces the same CIDs.

- A record has exactly four string fields: `cid_from`, `cid_to`, `neuron`, `claimed_at`.
- `cid_from`, `cid_to`, `neuron` are base58btc CID v0 (`Qm` + 44 chars). `neuron` is the CID of the author's SSH public key file. `claimed_at` is an RFC 3339 timestamp — the author's *claim*, see time semantics below.
- **Canonical bytes**: keys in the order above, compact JSON (no whitespace), exactly one trailing `\n`. The constrained charsets mean no JSON escaping can occur, so the bytes are trivially reproducible.
- **Self-addressing**: the file is stored as `links/<cid>.json` where `<cid>` is the CID v0 of the file's exact bytes. Readers reject a file whose raw bytes do not hash to its name — tampered or non-canonical files fail before any field is trusted.

Example (one line + `\n`, CID `QmZF4Nd4hAVHgLCW3YFEvtpDA52DX9z1vgX3CzH4L6yiwk`):

```json
{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","neuron":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr","claimed_at":"2026-07-16T00:00:00+00:00"}
```

Why JSON and not CSV/NUON: JSON is readable by every language and tool (and natively by nushell); CSV quoting is not canonical (the same reason nu-multiproof's merkle leaves hash parsed fields, not raw lines). Certificates are JSON too, for the same reach — nu-multiproof's `merkle prove`/`verify` speak JSON natively.

## Neuron repo layout

```
cybergraph/
  links/<link-cid>.json            # link records, one per file, self-addressed
  certs/<link-cid>.cert.json       # birth certificates (frozen `merkle prove` output)
  seals/<root-hex-12>/             # archival root statement + signatures, one per seal
  exports/<link-cid>/              # bundles built by `bundle` (default --out)
  imported/<neuron-cid>/<link-cid>/ # foreign bundles, verified on import, kept intact
  multiproofs/                     # nu-multiproof machinery (manifest, pubkeys, OTS)
```

A sha256 git backend (`git init --object-format=sha256`) is recommended; the merkle/certificate layer works on sha1 repos too. Note GitHub does not host sha256 repos — Codeberg and plain remotes do.

**Graph home.** The graph home is always `<git-root>/cybergraph/` — `init` creates it, every command finds it. Particles are referenced by CID, not path, so they never need to live under the graph home — or in the repo at all. The seal manifest covers only the graph subtree; a particle outside it still gets time-anchored the moment a sealed link mentions its CID, because showing bytes that hash to an anchored CID extends the anchor to those bytes. (Attesting a whole repo's files is a different job — use nu-multiproof's `seal` directly for that.)

## Birth certificate

`seal` stages `links/ certs/ seals/`, runs nu-multiproof's `seal` (manifest → merkle root → SSH signature → OTS stamp), then for every link that has no certificate yet extracts its inclusion proof and freezes it as `certs/<cid>.cert.json`. The seal's root statement and signatures are snapshotted under `seals/<root12>/`, because `multiproofs/tree-root.txt` is overwritten by the next seal while certificates must verify against the root they were born under. Certificates are never regenerated: `verify` and `bundle` always use the birth seal, not the repo's current root.

**Time semantics.** `claimed_at` is an unproven claim by the author, covered by the record's CID (it cannot be silently edited). The proof is the OTS anchor of the birth seal: "this record existed no later than Bitcoin block N". The earliest provable bound is set by the *first* seal, which is why certificates freeze — later seals only add newer roots. Provable granularity equals seal frequency, so seal on every append (a seal costs one signature plus one free OTS stamp for the whole batch). A fresh stamp reports `pending` until Bitcoin confirms (hours/days); any later seal in the origin repo upgrades it, but an already-exported bundle keeps its pending stamp until `ots upgrade` is run on it by hand. A provable *lower* bound ("created no earlier than") would need a recent Bitcoin block hash embedded in the record — deliberately out of v1.

**Neuron identity.** A neuron is the CID v0 of its public-key *file bytes* — the key comment included, no parsing or normalization. The same key material re-saved with a different comment is a different neuron. This is a feature, not an accident: identity-by-bytes keeps verification trivially reproducible (hash the file, compare — no SSH-format parsing in the trust path), and one keypair can act as several distinct neurons by varying the comment.

**Authorship.** A repo is one neuron's graph, sealed by that neuron's key: the root signature covers every catalogued record, so individual records carry no signature. Authorship travels in the certificate: a valid signature over the root statement plus the merkle path proves the neuron attested this exact record. Verification additionally checks the **neuron binding** — the record's `neuron` field must be the CID of a pubkey that validly signed the root statement. Without that check, anyone could re-seal someone else's record under their own key and the signature would still verify — against the wrong identity.

## Bundles, import, provenance

`bundle <link-cid>` assembles the portable artifact set in the layout nu-multiproof pins under "Verifying without the origin repo": the record at its `links/` path, the certificate, the birth seal's root statement + signatures, the signer pubkeys, and the OTS bundles committing to that root. Anyone verifies it offline with no access to the origin repo.

`import <bundle>` verifies first (merkle structure, signature, record self-addressing, neuron binding) and refuses invalid bundles loudly. A valid bundle lands intact under `imported/<neuron-cid>/<link-cid>/` — it remains the link's authority for authorship and birth time forever. Re-export is passing the directory along unchanged. Each importer's own `seal` then catalogues the imported files, adding a custody layer on top: "this repo held the bundle no later than block K" — provenance grows in layers without touching the original certificate.

## Dependencies

- [nu-multiproof](https://codeberg.org/nushell-prophet/nu-multiproof/) as a live sibling checkout at `../../ai-sandbox-dev-container/nu-multiproof` — resolved in exactly one file, `nu-cybergraph/_deps.nu`; edit it if your checkout lives elsewhere. Not a submodule: the two repos are co-developed and a pin would lag.
- `git`, `ssh-keygen`; `ipfs` CLI only for root CIDs (`seal --no-root-cid` avoids it — per-file CIDs are computed in pure nushell).

## Testing

Requires [nutest](https://github.com/vyadh/nutest) at `../../ai-sandbox-dev-container/nutest` (same sibling convention).

```nushell no-run
use toolkit.nu *; main test
```

Tests run fully offline (`--no-stamp --no-root-cid`); OTS and IPFS paths are exercised by nu-multiproof's own suite.
