# nu-cybergraph

A local cybergraph on a git backend: content-addressed link records between particles (files), with per-link authorship and birth-time proofs built on [nu-multiproof](https://codeberg.org/nushell-prophet/nu-multiproof/).

🚧 Proof of concept, agent-written, barely tested — do not treat as secure.

## Origins

The concept of Cybergraph was first invented and implemented by @mastercyb and @cyborgshead in the Bostrom blockchain. Cyberlink, Particle and Neuron are their terms too. Initially I resisted using them, but after tons of iterations I came to the conclusion that they deserve their own names, due to the uniqueness and substantiality of Cybergraph. Bostrom's *neuron* is the one word this repo no longer uses on its own account: following `bostrom-journal` bj002, the one who signs a cyberlink is the **signer** everywhere below, and `neuron` is kept only when quoting Bostrom.

## Concept

A **particle** is a content-addressed file (CID v0) — a CID becomes a particle when a link references it. A **link** is a directed edge between two particles, asserted by a **signer** — an identity that is itself just the CID of an SSH public key. A signer's cybergraph is a git repository of link records.

The design goal is cheap per-link portability: one signer can hand a single link to another with a verifiable author signature and a verifiable birth-time bound, **without** signing every record individually and without shipping its whole graph. The mechanism is a **birth certificate**: sign and OTS-stamp one merkle root per seal (nu-multiproof's machinery), then freeze each link's inclusion proof from the first seal that catalogued it.

## Quick start

```nushell no-run
use nu-cybergraph/

nu-cybergraph init                       # multiproof init + links/ certs/ under <repo>/cybergraph/
nu-cybergraph particle add "any text"    # publish content as particles/<cid>, get the CID
nu-cybergraph particle cat Qm…           # read a particle's exact bytes by its bare CID
nu-cybergraph link add Qm…from Qm…to     # write links/<cid>.json (non-CID args are published as particles first)
nu-cybergraph seal                       # sign + stamp the root, freeze new certificates
nu-cybergraph bundle Qm…link             # portable bundle → exports/<cid>/ (imported link: re-export + custody layer)
nu-cybergraph bundle Qm…link --to Qm…signer # …plus a signed handoff naming the recipient
nu-cybergraph import path/to/bundle      # verify, keep under imported/<signer>/<cid>/, write custody receipt
nu-cybergraph verify Qm…link             # own or imported, always against the birth seal
```

## Link record format

Pinned exactly (reference: `nu-cybergraph/_record.nu`; golden bytes and CID: `tests/test_record.nu`), so an independent implementation reproduces the same CIDs.

- A record has exactly three string fields — the cyberlink triple: `cid_from`, `cid_to`, `signer`.
- All three are base58btc CID v0 (`Qm` + 44 chars). `signer` is the CID of the author's SSH public key file. There is no timestamp in the record: time lives in the seal and, optionally, in a `claimed-at` convention edge — see time semantics below.
- **Canonical bytes**: keys in alphabetical order — byte order of the UTF-8 key bytes, locale-free — compact JSON (no whitespace), exactly one trailing `\n`. This is the one canon of the format, the same rule that serializes derived records (see `convention derive` below). The constrained charsets mean no JSON escaping can occur, so the bytes are trivially reproducible.
- **Self-addressing**: the file is stored as `links/<cid>.json` where `<cid>` is the CID v0 of the file's exact bytes. Readers reject a file whose raw bytes do not hash to its name — tampered or non-canonical files fail before any field is trusted. Because the record is exactly the triple, this self-address **equals the cyberlink's derived CID**: the same act asserted by the same signer is one CID for everyone, whenever it was recorded, and the file is the preimage of the act's address.
- **Triple guard**: a repeat of the triple is byte-identical, so `link add` refuses it by the file's existence — one act, one file, mirroring bostrom's consensus, which rejected a duplicate cyberlink. Re-assertion over time is a statement *about* the act (e.g. `convention claimed-at`), not a second copy of it.

Example — the golden record itself (one line + `\n`, CID `QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze`):

```json
{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","signer":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}
```

Why JSON and not CSV/NUON: JSON is readable by every language and tool (and natively by nushell); CSV quoting is not canonical (the same reason nu-multiproof's merkle leaves hash parsed fields, not raw lines). Certificates are JSON too, for the same reach — nu-multiproof's `merkle prove`/`verify` speak JSON natively.

## Particles and text arguments

`particle add` publishes arbitrary content as a self-addressed particle: a string argument or piped content (string or raw bytes — `open --raw doc.md | particle add`) is stored as `particles/<cid>` with its exact bytes, and the CID comes back. Idempotent: identical content is one particle.

`--ext` keeps a filename extension on the store file — `particle add --ext md` writes `particles/<cid>.md`, so a forge renders the particle as a document. The extension is presentation only, never part of the address: the CID is always the bare 46 characters, commands that read a particle accept only that (`particle cat Qm…` — a filename or path is refused) and resolve the store file whatever extension it carries. One CID, one file: a re-add of existing content under a different extension is a no-op (the first name wins), and a store holding two files for one CID fails fast on read. `particle cat` also verifies the bytes hash back to the CID before serving them, so a tampered store file fails instead of being returned.

Every particle argument of a write command (`link add`, all convention verbs) accepts either a CID v0 or content: a CID passes through untouched, anything else goes through the same store first and its CID is used. So `convention question Qm… "who reviews this?"` publishes the question text and writes the edge in one call. The one ambiguity — content that itself looks like a CID — has a composable escape hatch instead of a flag: publish it explicitly with `particle add` (which never treats input as an address) and pass the returned CID.

## Signer repo layout

```
cybergraph/
  links/<link-cid>.json            # link records, one per file, self-addressed
  particles/<cid>[.ext]            # self-addressed particles: instruction/address records and published content (extension optional, cosmetic)
  certs/<link-cid>.cert.json       # birth certificates (frozen `merkle prove` output)
  seals/<root-hex-12>/             # archival root statement + signatures, one per seal
  exports/<link-cid>/              # bundles built by `bundle` (default --out)
  imported/<signer-cid>/<link-cid>/ # foreign bundles, verified on import, kept intact
  receipts/<link-cid>.receipt.json # custody receipts for imported links (+ frozen *.receipt.cert.json)
  multiproofs/                     # nu-multiproof machinery (manifest, pubkeys, OTS)
```

A sha256 git backend (`git init --object-format=sha256`) is recommended; the merkle/certificate layer works on sha1 repos too. Note GitHub does not host sha256 repos — Codeberg and plain remotes do.

**Graph home.** The graph home is always `<git-root>/cybergraph/` — `init` creates it, every command finds it. Particles are referenced by CID, not path, so they never need to live under the graph home — or in the repo at all. The seal manifest covers only the graph subtree; a particle outside it still gets time-anchored the moment a sealed link mentions its CID, because showing bytes that hash to an anchored CID extends the anchor to those bytes. (Attesting a whole repo's files is a different job — use nu-multiproof's `seal` directly for that.)

## Conventions (bj002)

The twelve conventions of `bostrom-journal` bj002 — confirm, deny, update, quote, agree, disagree, pro, con, question, answer, author, same — *encode* an instruction for processing the graph as an ordinary edge. Concept and rationale live in bj002; this section is the mechanics. `nu-cybergraph convention <verb>` writes the edge through the same record path as `link add` (triple guard, self-addressing, author resolution), so it takes the same `--signer`/`--repo` controls. A thirteenth verb, `claimed-at`, is this repo's extension — it took over the `claimed_at` field removed from the link record (see time semantics).

Every convention stands on one primitive, the canonical record: **`convention derive`** takes a flat record, serializes it canonically — compact JSON, keys in alphabetical order, values strings only (no nesting: a reference to another record is its CID), exactly one trailing `\n` — and returns the CID v0 of those bytes, a **derived CID** (reproduce any with `printf '<record>\n' | ipfs add --only-hash --cid-version=0`). The record form is **this repo's experiment, not journal canon**: bj002's appendix defines `hash(x, y, …)` as the CID of the arguments comma-joined, and the journal issue that proposed records instead (bj002-1) was withdrawn on 2026-07-20 as a negative result — for the journal *text*, whose meaning drifted under the conversion; the code keeps testing the record form, where named fields and IPLD proximity are worth the price. The appendix's two special cases are just records here: the edge address is `derive {cid_from: A, cid_to: B}`, the cyberlink's derived CID is `derive {cid_from: A, cid_to: B, signer: S}`. This byte format is pinned by `tests/test_convention.nu`, same discipline as the record format — changing it breaks every derived CID. The link *file* record above IS the triple record under the same rule, so its self-address and the cyberlink's derived CID are one CID: acts are addressed by the double and triple alone (bj002 "Основы"), and the file in `links/` is the published preimage of that address.

An instruction lives in the *source* of its edge — a derived CID such as the CID of `{"op":"deny"}` — so the source is opaque. To make it readable, every convention publishes each record it mints — the instruction and the address records it references — as self-addressed particles under `particles/`: the record is its own preimage, so dereferencing the CID yields named fields with the real operand CIDs, and a text search for an operand's CID finds every record it participates in (bj002 "Reading instructions"). Particles are not sealed directly: a sealed convention edge names its source CID, and showing bytes that hash to a sealed CID time-anchors them — the same rule that anchors any particle named by a sealed link.

This table is the spec of the thirteen shapes; a record in source or target position means the CID of its canonical bytes. The header of `nu-cybergraph/convention.nu` restates it in the implementation's address-expression notation — same facts, second notation; if a shape ever changes, both move together.

| verb | edge written |
|---|---|
| `confirm A B` | `A → B` (the plain edge repeated — no instruction record) |
| `deny A B` / `deny A B N` | `{"op":"deny"} → {"cid_from":A,"cid_to":B}` (edge) / `→ {"cid_from":A,"cid_to":B,"signer":S}` (a signer's cyberlink) |
| `update A B C` | `{"cid_from":A,"cid_to":B,"op":"update"} → C` |
| `quote A B` | `{"about":A,"op":"quote"} → B` |
| `agree B` / `disagree B` | `{"op":"agree"\|"disagree"} → B` |
| `pro C B` / `con C B` | `{"about":C,"op":"pro"\|"con"} → B` |
| `question B Q` | `{"about":B,"op":"question"} → Q` |
| `answer B Q A` | `{"cid_from":{"about":B,"op":"question"},"cid_to":Q,"op":"answer"} → A` |
| `author B P` | `{"about":B,"op":"author"} → P` |
| `same P1 P2` | `{"about":P1,"op":"same"} → P2` |
| `claimed-at X T` | `{"about":X,"op":"claimed_at"} → T` (extension, not in bj002; T is an RFC 3339 particle) |

Reading and aggregation — counting confirmations, weighing signers, measuring consensus — are out of scope for now: one repo is one signer, so there is nothing to aggregate locally yet. `derive` gives a reader the address to look up; the counting is a later, cross-signer concern.

## Birth certificate

`seal` stages `links/ certs/ seals/ imported/ receipts/`, runs nu-multiproof's `seal` (manifest → merkle root → SSH signature → OTS stamp), then for every link that has no certificate yet extracts its inclusion proof and freezes it as `certs/<cid>.cert.json`. The seal's root statement and signatures are snapshotted under `seals/<root12>/`, because `multiproofs/tree-root.txt` is overwritten by the next seal while certificates must verify against the root they were born under. Certificates are never regenerated: `verify` and `bundle` always use the birth seal, not the repo's current root.

**Time semantics.** The record carries no timestamp: a time inside the record would fork the same act into different CIDs per recording moment, and it would still prove nothing. The one provable time is the OTS anchor of the birth seal: "this record existed no later than Bitcoin block N". The earliest provable bound is set by the *first* seal, which is why certificates freeze — later seals only add newer roots. Provable granularity equals seal frequency, so seal on every append (a seal costs one signature plus one free OTS stamp for the whole batch). A fresh stamp reports `pending` until Bitcoin confirms (hours/days); any later seal in the origin repo upgrades it, but an already-exported bundle keeps its pending stamp until `ots upgrade` is run on it by hand. An author who wants to *claim* a time states it as an ordinary edge — `convention claimed-at <cid> <rfc3339>` — optional, per-signer, and as unproven as the old in-record field was. A provable *lower* bound ("created no earlier than") would need a recent Bitcoin block hash embedded in the record — deliberately out of v1.

**Signer identity.** A signer is the CID v0 of its public-key *file bytes*, and the spec pins one canonical encoding for those bytes: `<type> <base64>` plus a trailing newline — no comment, no extra whitespace. Identity-by-bytes keeps verification trivially reproducible (hash the file, compare — no SSH-format parsing in the trust path); the canonical form keeps that hash stable and moves the one unavoidable parse to the boundary — `init` canonicalizes the key at registration, `import`/`verify` reject a bundle whose pubkey file is not canonical. The key comment is deliberately excluded: it is mutable metadata (`user@host` drifts across machines and re-saves) and would silently fork one key into several identities; the human label lives in the pubkey's file *name* instead. One keypair is one signer — distinct identities need distinct keypairs.

**Authorship.** A repo is one signer's graph, sealed by that signer's key: the root signature covers every catalogued record, so individual records carry no signature. Authorship travels in the certificate: a valid signature over the root statement plus the merkle path proves the signer attested this exact record. Verification additionally checks the **signer binding** — the record's `signer` field must be the CID of a pubkey that validly signed the root statement. Without that check, anyone could re-seal someone else's record under their own key and the signature would still verify — against the wrong identity.

## Bundles, import, provenance

`bundle <link-cid>` assembles the portable artifact set in the layout nu-multiproof pins under "Verifying without the origin repo": the record at its `links/` path, the certificate, the birth seal's root statement + signatures, the signer pubkeys, and the OTS bundles committing to that root. Anyone verifies it offline with no access to the origin repo.

`import <bundle>` verifies first (merkle structure, signature, record self-addressing, canonical pubkey form, signer binding, and every custody layer — below) and refuses invalid bundles loudly. A valid bundle lands intact under `imported/<signer-cid>/<link-cid>/` — it remains the link's authority for authorship and birth time forever, and the copy is read-only: re-export passes it along unchanged. Import also writes a **custody receipt** at `receipts/<link-cid>.receipt.json`, outside the read-only copy: `{link, signer, custodian, received_at, files, prev, handoff}`, where `files` is a path+sha256 manifest of the birth-bundle files as received, `prev` is the sha256 of the previous custody layer's receipt file (null for the first custodian), and `handoff` is the sha256 of the handoff the bundle arrived by (null when it arrived without one). The next `seal` catalogues the receipt and freezes its inclusion proof as `receipts/<link-cid>.receipt.cert.json` — the same freeze rule as birth certificates: the first seal sets the earliest provable custody bound.

`bundle` on an imported link **re-exports** it: the foreign bundle copied unchanged, plus this repo's custody layer appended under `custody/<n>-<signer12>/`. A layer is a proof bundle in the birth layout — the receipt at its `receipts/` path, its frozen proof at the layer root, the sealing root statement + signatures + pubkeys + OTS — so the same machinery verifies it: structure, signature, custodian binding (the receipt's `custodian` must be the CID of a validly-signing pubkey), `files` against the actual birth bytes, and the `prev` chain with contiguous layer numbering. The chain is what makes a dissemination path provable *in order*: layer *i*'s receipt commits to layer *i−1*'s receipt, so a stranger holding only the bundle can check "A authored it, then B held it no later than block K_B, then C no later than K_C" — provenance grows in layers without touching the original certificate, and each receipt stays constant-size (re-listing prior layers would grow the chain quadratically).

**Handoff.** Custody proves *holding*; without more, direction ("B → C") is only an inference from who held what. `bundle --to <signer-cid>` makes it a signed claim: a handoff file `<link-cid>.handoff.json` — `{schema, link, from, to, receipt, handed_at}` — plus a detached SSH signature, written at the bundle root (author) or inside the sender's custody layer (custodian). It is the one artifact signed directly rather than through a seal, because the bundle leaves at export time, before any later seal could catalogue it. `schema` is the constant `"cybergraph-handoff-v1"` and comes first, so the signed bytes open with a tag naming what they are: every SSH signature this toolchain makes is under the single `file` namespace, so a signature over untagged bytes could be replayed into any other context where the key signs bytes. Verification requires the token byte-exact — the JSON counterpart of nu-multiproof's one-line root statement. `receipt` pins the sha256 of the sender's receipt (null for the author), tying the claim to the exact chain state handed over; the recipient's receipt hashes the handoff back (its `handoff` field), so once the recipient seals, the sender's claim can no longer be stripped from the chain. Verification binds the signature to the sender's identity (a validly-signing pubkey whose CID is `from` — the handoff twin of the signer binding) and checks the seam: the previous holder's handoff must name the next layer's custodian, and `import` refuses a bundle handed to someone else — its own custody layer could never verify. The refusal is a fail-fast for honest importers, not a boundary against an interceptor (see the limits below). A handoff is optional (an open export names no recipient) and is a claim of *sending*, not a proof of delivery.

Three honest limits. The custody bounds are upper bounds: the chain proves each receipt existed before the next custodian's seal, not when a hop actually happened. A receipt pins the birth files byte-for-byte, so mutating an imported copy — including running `ots upgrade` inside it — breaks the `files` commitment of every receipt taken over those bytes; upgrade stamps in your own repo's `multiproofs/`, never inside `imported/`. And until the recipient seals, a handoff is just a file in the bundle: whoever holds the bytes can strip it (with its signature) and import the bundle as an open one, erasing the sender's directional claim — the seal, not the misaddressed-import refusal, is what makes a handoff permanent.

## Dependencies

- [nu-multiproof](https://codeberg.org/nushell-prophet/nu-multiproof/) as a live sibling checkout at `../../ai-sandbox-dev-container/nu-multiproof` — resolved in exactly one place, the `nu-cybergraph/_deps/` shims; edit them if your checkout lives elsewhere. Not a submodule: the two repos are co-developed and a pin would lag.
- `git` and `ssh-keygen`, nothing else: per-file, per-directory and root CIDs are all computed in pure nushell, so no `ipfs` CLI is needed.

## Testing

Requires [nutest](https://github.com/vyadh/nutest) at `../../ai-sandbox-dev-container/nutest` (same sibling convention).

```nushell no-run
use toolkit.nu *; main test
```

Tests run fully offline: `--no-stamp` is the only network the seal path has, and CIDs need no external call. The OTS path is exercised by nu-multiproof's own suite.
