# nu-cybergraph

A local cybergraph on a git backend: content-addressed link records between particles (files), with per-link authorship and birth-time proofs built on [nu-multiproof](https://codeberg.org/nushell-prophet/nu-multiproof/).

🚧 Proof of concept, agent-written, barely tested — do not treat as secure. The concept it implements is developed in the `bostrom-journal` (bj003).

## Concept

A **particle** is a content-addressed file (CID v0) — a CID becomes a particle when a link references it. A **link** is a directed edge between two particles, asserted by a **neuron** — an identity that is itself just the CID of an SSH public key. A neuron's cybergraph is a git repository of link records.

The design goal is cheap per-link portability: one neuron can hand a single link to another with a verifiable author signature and a verifiable birth-time bound, **without** signing every record individually and without shipping its whole graph. The mechanism is a **birth certificate**: sign and OTS-stamp one merkle root per seal (nu-multiproof's machinery), then freeze each link's inclusion proof from the first seal that catalogued it.

## Quick start

```nushell no-run
use nu-cybergraph/

nu-cybergraph init                       # multiproof init + links/ certs/ under <repo>/cybergraph/
nu-cybergraph link add Qm…from Qm…to     # write links/<cid>.json
nu-cybergraph seal                       # sign + stamp the root, freeze new certificates
nu-cybergraph bundle Qm…link             # portable bundle → exports/<cid>/ (imported link: re-export + custody layer)
nu-cybergraph bundle Qm…link --to Qm…neuron # …plus a signed handoff naming the recipient
nu-cybergraph import path/to/bundle      # verify, keep under imported/<neuron>/<cid>/, write custody receipt
nu-cybergraph verify Qm…link             # own or imported, always against the birth seal
```

## Link record format

Pinned exactly (reference: `nu-cybergraph/_record.nu`; golden bytes and CID: `tests/test_record.nu`), so an independent implementation reproduces the same CIDs.

- A record has exactly four string fields: `cid_from`, `cid_to`, `neuron`, `claimed_at`.
- `cid_from`, `cid_to`, `neuron` are base58btc CID v0 (`Qm` + 44 chars). `neuron` is the CID of the author's SSH public key file. `claimed_at` is an RFC 3339 timestamp — the author's *claim*, see time semantics below.
- **Canonical bytes**: keys in the order above, compact JSON (no whitespace), exactly one trailing `\n`. The constrained charsets mean no JSON escaping can occur, so the bytes are trivially reproducible.
- **Self-addressing**: the file is stored as `links/<cid>.json` where `<cid>` is the CID v0 of the file's exact bytes. Readers reject a file whose raw bytes do not hash to its name — tampered or non-canonical files fail before any field is trusted.
- **Triple guard**: `link add` refuses a record whose `(cid_from, cid_to, neuron)` triple already exists in `links/` — with `claimed_at` inside the record a repeat would be a new record, not a new vote; a deliberate re-assertion over time takes `--reassert`. Dedupe policy for readers is keep-earliest: the first record's certificate carries the edge's earliest provable time bound.

Example (one line + `\n`, CID `QmYzHh4HXjzeJ87SwRHS5GovKGcqAyUimwgiZNSxjfGfCa`):

```json
{"cid_from":"QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV","cid_to":"Qmc9pm5gQqDwJMiFTmFEuTxRhSy5Cn2yt7NZh1LrxmMhSi","neuron":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr","claimed_at":"2026-07-16T00:00:00+00:00"}
```

Why JSON and not CSV/NUON: JSON is readable by every language and tool (and natively by nushell); CSV quoting is not canonical (the same reason nu-multiproof's merkle leaves hash parsed fields, not raw lines). Certificates are JSON too, for the same reach — nu-multiproof's `merkle prove`/`verify` speak JSON natively.

## Neuron repo layout

```
cybergraph/
  links/<link-cid>.json            # link records, one per file, self-addressed
  particles/<derived-cid>          # preimages of derived CIDs (convention sources), self-addressed
  certs/<link-cid>.cert.json       # birth certificates (frozen `merkle prove` output)
  seals/<root-hex-12>/             # archival root statement + signatures, one per seal
  exports/<link-cid>/              # bundles built by `bundle` (default --out)
  imported/<neuron-cid>/<link-cid>/ # foreign bundles, verified on import, kept intact
  receipts/<link-cid>.receipt.json # custody receipts for imported links (+ frozen *.receipt.cert.json)
  multiproofs/                     # nu-multiproof machinery (manifest, pubkeys, OTS)
```

A sha256 git backend (`git init --object-format=sha256`) is recommended; the merkle/certificate layer works on sha1 repos too. Note GitHub does not host sha256 repos — Codeberg and plain remotes do.

**Graph home.** The graph home is always `<git-root>/cybergraph/` — `init` creates it, every command finds it. Particles are referenced by CID, not path, so they never need to live under the graph home — or in the repo at all. The seal manifest covers only the graph subtree; a particle outside it still gets time-anchored the moment a sealed link mentions its CID, because showing bytes that hash to an anchored CID extends the anchor to those bytes. (Attesting a whole repo's files is a different job — use nu-multiproof's `seal` directly for that.)

## Conventions (bj002)

The twelve conventions of `bostrom-journal` bj002 — confirm, deny, update, quote, agree, disagree, pro, con, question, answer, author, same — *encode* an instruction for processing the graph as an ordinary edge. Concept and rationale live in bj002; this section is the mechanics. `nu-cybergraph convention <verb>` writes the edge through the same record path as `link add` (triple guard, self-addressing, author/time resolution), so it takes the same `--neuron`/`--claimed-at`/`--repo`/`--reassert` controls.

Every convention stands on one primitive, the journal's `hash(x, y, …)`: **`convention derive`** joins the argument CID strings with commas and takes the CID v0 of those exact bytes — no trailing newline (reproduce any with `printf '<preimage>' | ipfs add --cid-version=0`). The two special cases of the appendix fall out of the same call: the edge address is `derive <from> <to>`, the cyberlink's derived CID is `derive <from> <to> <neuron>`. This byte format is pinned by `tests/test_convention.nu`, same discipline as the record format — changing it breaks every derived CID.

An instruction lives in the *source* of its edge — a derived CID such as `hash("deny")` or `hash("update", hash(A,B))` — so the source is opaque. To make it readable, every convention also publishes the **preimage** of each derived CID it mints (the string `"update,Qm…"`) as a self-addressed particle under `particles/`, so a reader can dereference the source and recognise the instruction (bj002 "Reading instructions"). Particles are not sealed directly: a sealed convention edge names its source CID, and showing bytes that hash to a sealed CID time-anchors them — the same rule that anchors any particle named by a sealed link.

This table is the spec of the twelve shapes. The header of `nu-cybergraph/convention.nu` restates it in the implementation's address-expression notation (`[x y …]` = `hash(x, y, …)`) — same facts, second notation; if a shape ever changes, both move together.

| verb | edge written |
|---|---|
| `confirm A B` | `A → B` (the plain edge repeated — no source, no preimage) |
| `deny A B` / `deny A B N` | `hash("deny") → hash(A,B)` (edge) / `→ hash(A,B,N)` (a neuron's cyberlink) |
| `update A B C` | `hash("update", hash(A,B)) → C` |
| `quote A B` | `hash("quote", A) → B` |
| `agree B` / `disagree B` | `hash("agree"\|"disagree") → B` |
| `pro C B` / `con C B` | `hash("pro"\|"con", C) → B` |
| `question B Q` | `hash("question", B) → Q` |
| `answer B Q A` | `hash("answer", hash(hash("question",B), Q)) → A` |
| `author B P` | `hash("author", B) → P` |
| `same P1 P2` | `hash("same", P1) → P2` |

Reading and aggregation — counting confirmations, weighing neurons, measuring consensus — are out of scope for now: one repo is one neuron, so there is nothing to aggregate locally yet. `derive` gives a reader the address to look up; the counting is a later, cross-neuron concern.

## Birth certificate

`seal` stages `links/ certs/ seals/ imported/`, runs nu-multiproof's `seal` (manifest → merkle root → SSH signature → OTS stamp), then for every link that has no certificate yet extracts its inclusion proof and freezes it as `certs/<cid>.cert.json`. The seal's root statement and signatures are snapshotted under `seals/<root12>/`, because `multiproofs/tree-root.txt` is overwritten by the next seal while certificates must verify against the root they were born under. Certificates are never regenerated: `verify` and `bundle` always use the birth seal, not the repo's current root.

**Time semantics.** `claimed_at` is an unproven claim by the author, covered by the record's CID (it cannot be silently edited). The proof is the OTS anchor of the birth seal: "this record existed no later than Bitcoin block N". The earliest provable bound is set by the *first* seal, which is why certificates freeze — later seals only add newer roots. Provable granularity equals seal frequency, so seal on every append (a seal costs one signature plus one free OTS stamp for the whole batch). A fresh stamp reports `pending` until Bitcoin confirms (hours/days); any later seal in the origin repo upgrades it, but an already-exported bundle keeps its pending stamp until `ots upgrade` is run on it by hand. A provable *lower* bound ("created no earlier than") would need a recent Bitcoin block hash embedded in the record — deliberately out of v1.

**Neuron identity.** A neuron is the CID v0 of its public-key *file bytes*, and the spec pins one canonical encoding for those bytes: `<type> <base64>` plus a trailing newline — no comment, no extra whitespace. Identity-by-bytes keeps verification trivially reproducible (hash the file, compare — no SSH-format parsing in the trust path); the canonical form keeps that hash stable and moves the one unavoidable parse to the boundary — `init` canonicalizes the key at registration, `import`/`verify` reject a bundle whose pubkey file is not canonical. The key comment is deliberately excluded: it is mutable metadata (`user@host` drifts across machines and re-saves) and would silently fork one key into several identities; the human label lives in the pubkey's file *name* instead. One keypair is one neuron — distinct identities need distinct keypairs.

**Authorship.** A repo is one neuron's graph, sealed by that neuron's key: the root signature covers every catalogued record, so individual records carry no signature. Authorship travels in the certificate: a valid signature over the root statement plus the merkle path proves the neuron attested this exact record. Verification additionally checks the **neuron binding** — the record's `neuron` field must be the CID of a pubkey that validly signed the root statement. Without that check, anyone could re-seal someone else's record under their own key and the signature would still verify — against the wrong identity.

## Bundles, import, provenance

`bundle <link-cid>` assembles the portable artifact set in the layout nu-multiproof pins under "Verifying without the origin repo": the record at its `links/` path, the certificate, the birth seal's root statement + signatures, the signer pubkeys, and the OTS bundles committing to that root. Anyone verifies it offline with no access to the origin repo.

`import <bundle>` verifies first (merkle structure, signature, record self-addressing, canonical pubkey form, neuron binding, and every custody layer — below) and refuses invalid bundles loudly. A valid bundle lands intact under `imported/<neuron-cid>/<link-cid>/` — it remains the link's authority for authorship and birth time forever, and the copy is read-only: re-export passes it along unchanged. Import also writes a **custody receipt** at `receipts/<link-cid>.receipt.json`, outside the read-only copy: `{link, neuron, custodian, received_at, files, prev, handoff}`, where `files` is a path+sha256 manifest of the birth-bundle files as received, `prev` is the sha256 of the previous custody layer's receipt file (null for the first custodian), and `handoff` is the sha256 of the handoff the bundle arrived by (null when it arrived without one). The next `seal` catalogues the receipt and freezes its inclusion proof as `receipts/<link-cid>.receipt.cert.json` — the same freeze rule as birth certificates: the first seal sets the earliest provable custody bound.

`bundle` on an imported link **re-exports** it: the foreign bundle copied unchanged, plus this repo's custody layer appended under `custody/<n>-<neuron12>/`. A layer is a proof bundle in the birth layout — the receipt at its `receipts/` path, its frozen proof at the layer root, the sealing root statement + signatures + pubkeys + OTS — so the same machinery verifies it: structure, signature, custodian binding (the receipt's `custodian` must be the CID of a validly-signing pubkey), `files` against the actual birth bytes, and the `prev` chain with contiguous layer numbering. The chain is what makes a dissemination path provable *in order*: layer *i*'s receipt commits to layer *i−1*'s receipt, so a stranger holding only the bundle can check "A authored it, then B held it no later than block K_B, then C no later than K_C" — provenance grows in layers without touching the original certificate, and each receipt stays constant-size (re-listing prior layers would grow the chain quadratically).

**Handoff.** Custody proves *holding*; without more, direction ("B → C") is only an inference from who held what. `bundle --to <neuron-cid>` makes it a signed claim: a handoff file `<link-cid>.handoff.json` — `{link, from, to, receipt, handed_at}` — plus a detached SSH signature, written at the bundle root (author) or inside the sender's custody layer (custodian). It is the one artifact signed directly rather than through a seal, because the bundle leaves at export time, before any later seal could catalogue it. `receipt` pins the sha256 of the sender's receipt (null for the author), tying the claim to the exact chain state handed over; the recipient's receipt hashes the handoff back (its `handoff` field), so once the recipient seals, the sender's claim can no longer be stripped from the chain. Verification binds the signature to the sender's identity (a validly-signing pubkey whose CID is `from` — the handoff twin of the neuron binding) and checks the seam: the previous holder's handoff must name the next layer's custodian, and `import` refuses a bundle handed to someone else — its own custody layer could never verify. The refusal is a fail-fast for honest importers, not a boundary against an interceptor (see the limits below). A handoff is optional (an open export names no recipient) and is a claim of *sending*, not a proof of delivery.

Three honest limits. The custody bounds are upper bounds: the chain proves each receipt existed before the next custodian's seal, not when a hop actually happened. A receipt pins the birth files byte-for-byte, so mutating an imported copy — including running `ots upgrade` inside it — breaks the `files` commitment of every receipt taken over those bytes; upgrade stamps in your own repo's `multiproofs/`, never inside `imported/`. And until the recipient seals, a handoff is just a file in the bundle: whoever holds the bytes can strip it (with its signature) and import the bundle as an open one, erasing the sender's directional claim — the seal, not the misaddressed-import refusal, is what makes a handoff permanent.

## Dependencies

- [nu-multiproof](https://codeberg.org/nushell-prophet/nu-multiproof/) as a live sibling checkout at `../../ai-sandbox-dev-container/nu-multiproof` — resolved in exactly one file, `nu-cybergraph/_deps.nu`; edit it if your checkout lives elsewhere. Not a submodule: the two repos are co-developed and a pin would lag.
- `git`, `ssh-keygen`; `ipfs` CLI only for root CIDs (`seal --no-root-cid` avoids it — per-file CIDs are computed in pure nushell).

## Testing

Requires [nutest](https://github.com/vyadh/nutest) at `../../ai-sandbox-dev-container/nutest` (same sibling convention).

```nushell no-run
use toolkit.nu *; main test
```

Tests run fully offline (`--no-stamp --no-root-cid`); OTS and IPFS paths are exercised by nu-multiproof's own suite.
