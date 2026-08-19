# Cybergraph format specification v1

What an independent implementation, in any language, needs in order to write and read the same artifacts as `nu-cybergraph`: the byte formats, the folder structure, the key format, and the procedures that produce and check them.

This document pins mechanics only. Reasons live in `README.md`; the concept lives in `bostrom-journal` bj002 and bj003. Where the two disagree with the code, the code and its golden tests win, and the divergence is a bug in the prose.

**Pre-1.0.** There is no backwards compatibility to keep. Any change to section 2 or 3 recomputes every CID in every graph and is a format version bump, not an edit.

MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Terms

| term | meaning |
|---|---|
| particle | a carrier of meaning: its content is the bytes of a file, its name is the CID v0 of those bytes |
| vertex | the role a particle takes when its CID stands in an edge, not a second thing |
| edge | the pair `{cid_from, cid_to}` — the unit of the operational layer; one address shared by every signer asserting it |
| link, cyberlink | an edge asserted by one signer — the triple; its file holds the pair, the signer lives in the path |
| signer | an identity: the CID v0 of an SSH public key file in canonical form |
| graph home | `<git-root>/cybergraph/` — one signer's whole graph |
| seal | one signing moment: manifest → merkle root → SSH signature → OTS stamp |
| birth certificate | the inclusion proof from the first seal that catalogued a link, frozen |
| bundle | a directory holding everything needed to verify one link with no origin repo |

## 2. Primitives

### 2.1 CID v0

Every address in this format is a CID v0 of concrete bytes: base58btc, always `Qm` followed by 44 characters.

```
^Qm[1-9A-HJ-NP-Za-km-z]{44}$
```

It is IPFS UnixFS over DAG-PB, and equals what the reference client reports for `ipfs add --only-hash --quieter --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144`. The construction is written out below so that no IPFS library is needed.

**Constants.** Payload chunk size 262144 bytes. Links per intermediate node 174 (go-unixfs `DefaultLinksPerBlock`: an 8 KiB block target over ~47 bytes per link). Directory shard threshold 262144, each entry estimated as its name length plus 34.

**Varint** is unsigned LEB128: while the value is 128 or more, emit `(value mod 128) | 0x80` and divide the value by 128; then emit what remains. Negative values have no encoding and MUST be refused rather than two's-complemented.

**Protobuf framing.** A length-delimited field is `<tag byte><length varint><bytes>`. Only these fields appear, and they are emitted in the order listed:

| message | field | tag | type |
|---|---|---|---|
| PBNode | Links | `0x12` | length-delimited, repeated — one per link, **before** Data |
| PBNode | Data | `0x0a` | length-delimited — the UnixFS message |
| PBLink | Hash | `0x0a` | length-delimited — the child's CID **bytes**: `0x12 0x20` + the 32-byte digest |
| PBLink | Name | `0x12` | length-delimited — always emitted, `0x12 0x00` for a file chunk link |
| PBLink | Tsize | `0x18` | varint |
| UnixFS | Type | `0x08` | varint — 2 file, 1 directory |
| UnixFS | Data | `0x12` | length-delimited — the payload chunk |
| UnixFS | filesize | `0x18` | varint |
| UnixFS | blocksizes | `0x20` | varint, repeated — one per child, in link order, each the child's **filesize** |

Besides its digest, a node carries two numbers: **Tsize**, the serialized length of its own block plus the Tsize of every node beneath it, and **filesize**, the payload bytes it covers (file nodes only).

**Leaf node** — one chunk of payload. Its UnixFS message is Type = 2, then Data = the chunk, then filesize = the chunk length. An **empty file omits the Data field entirely** — it does not carry a zero-length one — but still emits `filesize = 0`: Data is the only conditional field, and protobuf's habit of dropping default-valued scalars does not apply here. The block is that message wrapped as PBNode.Data, with no links.

**Balanced fold.** Split the payload into 262144-byte chunks in order and make each a leaf node; an empty payload gives exactly one leaf over zero bytes. Then, while more than one node remains, take the nodes in order, cut them into consecutive batches of 174, and replace each batch with a branch node over it.

**Branch node.** The block is its children's links in order — each `PBLink` with an empty Name — followed by PBNode.Data holding UnixFS Type = 2, filesize = the sum of the children's filesizes, and one blocksizes entry per child in link order. Each blocksizes entry is that child's **filesize** — the payload bytes it covers — and not the size of its block, which the field's name invites. A branch carries no UnixFS Data field.

**Directory node.** The block is one PBLink per entry, Name being the entry name, sorted **byte-wise by name** — link order is part of what the CID commits to — followed by PBNode.Data holding UnixFS Type = 1 and nothing else. If the sum over entries of (byte length of the name + 34) exceeds 262144, IPFS switches that directory to a HAMT shard whose CID this construction does not reproduce: refuse it, rather than emit a basic-directory CID no IPFS client agrees with.

**The CID.** Take sha2-256 of the serialized block, prefix `0x12 0x20` (multihash: sha2-256, 32 bytes), and base58btc-encode the resulting 34 bytes with the alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`, emitting one leading `1` per leading zero byte. That prefix is constant, which is why every CID v0 renders as `Qm` plus 44 characters.

Directory CIDs are needed only by the manifest layer (7). Reference implementation: nu-multiproof `nu-multiproof/_cid-helpers.nu`; vectors in 9.

### 2.2 Canonical record bytes

One serialization rule covers every record this format hashes — link records and derived records alike.

- The record MUST be flat, and every value MUST be a string. A reference to another record is that record's CID, never a nested object.
- Keys are sorted by the byte order of their UTF-8 bytes: locale-free, case-sensitive.
- Compact JSON — no whitespace anywhere outside string values.
- Exactly one trailing `\n`.

A **derived CID** is the CID v0 of those bytes. Reproduce any of them with `printf '<record>\n' | ipfs add --only-hash --cid-version=0`.

All values used in practice are CIDs and reserved `op` words, whose charsets contain nothing JSON escapes, so the bytes are reproducible without an escaping policy.

### 2.3 Field types

| type | rule |
|---|---|
| CID | `^Qm[1-9A-HJ-NP-Za-km-z]{44}$` |
| timestamp | `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z\|[+-]\d{2}:\d{2})$` — RFC 3339, fractional seconds optional |
| hash | `^[0-9a-f]{64}$` — sha256, lowercase hex |

Validation is by exact key set: a record with an unknown or missing key MUST be refused before any value is read.

### 2.4 Signer identity — the key format

A signer is the **CID v0 of its public key file bytes**, and those bytes have exactly one legal form:

```
<type> <base64>\n
```

No comment, no leading or trailing whitespace, no second line, no BOM. The key comment is excluded deliberately: it is mutable metadata, and keeping it would fork one key into several identities.

`<type>` MUST be one of:

```
ssh-rsa  ssh-ed25519
ecdsa-sha2-nistp256  ecdsa-sha2-nistp384  ecdsa-sha2-nistp521
sk-ssh-ed25519@openssh.com  sk-ecdsa-sha2-nistp256@openssh.com
```

Certificates (`*-cert-v01@openssh.com`) are refused. `ssh-dss` is refused: OpenSSH 10 removed DSA, so such a key could never be verified.

`<base64>` MUST be the encoding OpenSSH itself writes for that key. Checking the type prefix is not enough — RFC 4251 permits a redundant leading zero byte in an RSA mpint, and OpenSSH trims it while parsing, so a padded copy of a key loads fine, reports the same fingerprint, and addresses to a *different* CID. The reference implementation settles this by round-tripping the line through `ssh-keygen -e -m RFC4716` and `ssh-keygen -i -m RFC4716` and requiring a fixed point. An implementation MUST make an equivalent check; accepting the bytes as given hands one key a second identity.

Canonicalization is enforced at exactly two boundaries: registration, and every read of a bundle's `multiproofs/pubkeys/` at verification — including a bundle built from this repo's own key, so the registered key is re-checked whenever an own link is verified. A key is never re-checked *in place*, so one that reached a trust list by any other route keeps whatever bytes it has, and its CID identity differs from the same key stored through registration.

Two derived names, not to be confused:

| name | value | used for |
|---|---|---|
| signer CID | CID v0 of the canonical file bytes | the signer directory a link file lives in; the `signer` field of the triple particle; the signer binding at verification |
| fingerprint | sha256 of the base64-decoded key blob, lowercase hex | the pubkey filename, the middle segment of a `.sig` filename, nu-multiproof's principal |

A pubkey file's **name is decoration**. Identity comes from the bytes inside it. A verifier MUST NOT match a signer CID by filename — hash the file contents and compare.

A graph home has exactly one **authoring** identity, while `multiproofs/pubkeys/` MAY hold several keys — the two are different questions. The directory is nu-multiproof's trust list — the keys whose signatures this format accepts — and verification reads every valid signature over a root (8), so a key registered beside the authoring one can add a signature but never take authorship. The authoring identity is the key the checkout itself signs with — `user.signingKey` in its git config, the same key `seal` signs the root with — because a record's signer MUST be a key that validly signed the root cataloguing it (8) or the binding fails. An implementation MUST resolve it by key material: the canonical form of the configured key equals a registered file's bytes, never a filename match. The reference implementation refuses to write when no key is configured at all, when the configured key is not registered, and when nothing is registered — a single registered key is not an answer either, since the trust list is exactly where a key belonging to someone else is meant to sit. A command with an operator-facing `--key` (export) resolves that key instead of the config. Registration stays deliberate: `init` establishes the identity and MUST NOT grow a trust list that already holds one, undoing what such a run added — a trust list states whose signatures a graph accepts, so a key must never join it by accident. A key joins beside the identity only by an explicit route, `init --co-signer <key>.pub` in the reference implementation, which registers and establishes nothing. `seal` refuses only the zero case.

### 2.5 SSH signatures

Every signature in this format is a detached SSH signature (SSHSIG) over a file's exact bytes, made and verified under the namespace **`file`** — one fixed value, never a caller's choice. SSHSIG puts the namespace inside the signed preimage, so this is not cosmetic: a verifier using any other value rejects every good signature. It is fixed rather than configurable because the value is interpolated into the rendered trust list, where a crafted namespace once injected `cert-authority` and made every registered key trusted for anything.

Domain separation therefore has to live in the signed bytes. That is why the root statement is a single line opening with the token `multiproof-merkle-v1` (7) rather than a bare hash.

A signature sits beside the file it signs, named `<file>.<fingerprint>.sig`. Verification renders its trust list from the proof directory's own `multiproofs/pubkeys/`, one line per key: `<fingerprint> namespaces="file" <type> <base64>`.

## 3. Repository layout

The graph home is always `<git-root>/cybergraph/`. A particle referenced by a link need not have its bytes there, or in the repo at all — links name CIDs, not paths.

```
cybergraph/
  <signer-cid>/<edge-cid>.json              # link records: pair in the file, signer in the path  3.1
  particles/<cid>[.ext]                     # the particle store, self-addressed                  3.2
  certs/<signer-cid>/<edge-cid>.cert.json   # frozen birth certificates, mirroring the layout     3.3
  seals/<root-hex-12>/                      # per-seal root statement + signatures                3.4
  exports/<signer-cid>/<edge-cid>/          # bundles this repo built                             6
  multiproofs/pubkeys/<fingerprint>.pub     # the registered key, canonical bytes                 2.4
  multiproofs/                              # the rest of the proof layer                         7
```

Signer directories sit at the graph root and are told from the reserved directories by form alone: a directory named by a CID v0 is a signer's, and the reserved names never match that pattern. The pubkey filename is the reference implementation's choice and carries no authority — see 2.4.

The signer directories, `certs/` and `seals/` are what a seal stages into git; `particles/` and `exports/` are not staged by the seal (see 5).

A sha256 git backend (`git init --object-format=sha256`) is recommended. The format works on sha1 repos too.

### 3.1 Link record — `<signer-cid>/<edge-cid>.json`

The atomic edge, in its signer's directory. The file holds exactly the pair, two keys, both CIDs, nothing else:

```json
{"cid_from":"Qm…","cid_to":"Qm…"}
```

- Serialized by the canonical rule (2.2), so key order is alphabetical — `cid_from`, `cid_to` — compact, one trailing `\n`.
- The filename stem MUST be the CID v0 of the file's exact bytes — the **edge address**, `derive {cid_from, cid_to}` under 2.2. Two signers stating one edge share one filename, each in their own directory.
- The signer is **not in the bytes**: it is the directory name, which MUST be a CID v0. What binds the pair to the signer is the seal — the path enters the signed root (5) — so a file moved into another signer's directory breaks its own proof. A reader checks the directory's *form* only; the binding is checked at verification (8).
- There is **no timestamp**. A time inside the record would fork one act into a different CID per recording moment. Provable time comes from the seal (5); a claimed time is an ordinary edge (`claimed-at`, section 4).

The cyberlink — the triple `derive {cid_from, cid_to, signer}` — is still defined and still computed: pair from the file, signer from the path. It stopped being the file's name.

**Publishing the triple.** A writer MUST publish the triple record as a store file (3.2) when it writes the link — the same rule section 4 puts on every record a convention mints, and this is the same record `confirm A B S` mints as its target. Without the preimage the cyberlink's derived CID is one no later act can dereference. A writer MUST also still publish the pair record as a store file, even though the link file holds the same bytes: the store (3.2) is the one place derived CIDs are dereferenced, and `confirm A B` / `deny A B` mint the same pair record as their target. Publishing is idempotent, so a repeat, a second signer of the same edge, and a convention minting the same pair all write nothing new.

A reader MUST enforce both addressing rules, from a **single** read of the bytes:

1. CID v0 of the raw bytes equals the filename stem.
2. Those raw bytes equal the canonical serialization of the parsed record.

Rule 2 is not redundant. Reordered keys, added whitespace, or a duplicate key each hash to some other CID and would pass rule 1 under that name — giving one act two addresses. Decode as UTF-8 explicitly; guessing the encoding lets a UTF-16 file parse to the same pair under a different CID.

**Triple guard.** The path IS the triple — signer in the directory, edge in the filename — so a repeat of the same act lands on the same path, and a writer MUST return the existing record rather than write a second file. One act, one file. The no-op still re-reads and re-checks the file on disk first, so a corrupted record fails loudly instead of reading as a successful repeat.

### 3.2 Particle store — `particles/<cid>[.ext]`

Arbitrary content published as a self-addressed file, storing the exact bytes: no newline appended, no encoding transform.

- The address is always the bare 46-character CID. An extension is a presentation hint only (a forge renders `.md`), matching `^[A-Za-z0-9]+(\.[A-Za-z0-9]+)*$`.
- One CID, one file. Re-adding existing content under a different extension is a no-op — the first name wins. A store holding two files for one CID is broken and MUST fail fast on read, never silently pick one.
- A reader MUST hash the bytes back to the CID before serving them.
- Absence is ordinary for a reader: a link names CIDs and the bytes need not be local. Absence and tampering MUST stay distinguishable — an optional read returns nothing for a CID the store does not hold, and still raises for a file that fails its hash.

The store holds content published by a user, the instruction and address records minted by conventions (section 4), and the pair and triple records of every link (3.1). Publishing the derived records is what makes a derived CID readable — the record is its own preimage.

Store files are not sealed directly. A file is time-anchored the moment a sealed link names its CID, because showing bytes that hash to an anchored CID extends the anchor to those bytes.

### 3.3 Birth certificate — `certs/<signer-cid>/<edge-cid>.cert.json`

The inclusion proof extracted from the **first** seal that catalogued the link, frozen forever, filed mirroring the link layout — the signer's directory, the edge's name. JSON, 2-space indent (the bytes are not addressed, so formatting is free):

```json
{
  "schema": "multiproof-merkle-v1",
  "leaf": {
    "filepath": "<signer-cid>/<edge-cid>.json",
    "content_sha256": "<64 hex>",
    "content_git": "<40 or 64 hex>",
    "content_cid": "<Qm…>"
  },
  "path": [ {"side": "left|right", "hash": "<64 hex>"} ],
  "root": "<64 hex>"
}
```

`path` is leaf-to-root order and `side` names the **sibling**'s position. `root` is self-description only — a verifier folds to the root in the *signed statement*, never to this copy.

**Never regenerated.** Its OTS anchor is the link's earliest provable time bound; later seals only mint newer roots. `verify` and `bundle` MUST use the birth seal, never the repo's current root.

Whatever stands at a certificate path MUST be that certificate. Deciding "already certified" from bare file existence is not enough: a directory, an empty file, or a genuine proof whose `leaf.filepath` names a different link each leave the link uncertified while it is catalogued, so the certificate a later seal writes names a later root than the link's birth. The reference implementation runs this check at seal time only — `verify` and `bundle` still branch on bare existence, so junk at a certificate path reaches them as a crash rather than a verdict.

### 3.4 Seal snapshot — `seals/<root-hex-12>/`

The directory name is the first 12 characters of the seal's merkle root hex. It holds that seal's root statement and its signatures, copied out of `multiproofs/` before the next seal overwrites them:

```
seals/<root12>/tree-root.txt
seals/<root12>/tree-root.txt.<fingerprint>.sig   # and/or the bare tree-root.txt.sig
```

This is what makes a frozen certificate exportable: certificates verify against the root they were born under, and `multiproofs/tree-root.txt` is overwritten every seal.

## 4. Conventions — instructions as ordinary edges

A convention encodes an instruction for processing the graph as a plain edge whose **source** is a derived CID. The grammar has one atom and one constructor:

- An **address expression** is a leaf (an operand) or a record whose values are themselves expressions.
- An operand is an address when it matches the CID v0 pattern of 2.3. Otherwise it is content: a string naming an existing file publishes that file's bytes, any other string publishes itself, and a path-shaped string naming nothing MUST be refused rather than published as its own text. So content that itself reads as a CID, or as a path, cannot be passed as content — publish it first and pass the CID back.
- A nested record resolves to its derived CID, so the final record is always flat and 2.2 applies.
- The single exception is the value of an `op` key: a reserved word of the format, used verbatim, never treated as an operand.

Every record passed through MUST be published as a file under `particles/` — that is what lets a reader dereference an opaque source CID and get named fields back.

Sixteen verbs. Twelve are bj002 conventions; `repeat` is edge repetition (bj002 names it beside the conventions, not among them — it puts no special CID in the source); `claimed-at`, `update-file` and `translation` are this format's extensions, which bj002's open set permits.

| verb | edge written |
|---|---|
| `repeat A B` | `A → B` |
| `confirm A B` | `{"op":"confirm"} → {"cid_from":A,"cid_to":B}` |
| `confirm A B S` | `{"op":"confirm"} → {"cid_from":A,"cid_to":B,"signer":S}` |
| `deny A B` | `{"op":"deny"} → {"cid_from":A,"cid_to":B}` |
| `deny A B S` | `{"op":"deny"} → {"cid_from":A,"cid_to":B,"signer":S}` |
| `agree B` / `disagree B` | `{"op":"agree"}` / `{"op":"disagree"} → B` |
| `quote A B` | `{"about":A,"op":"quote"} → B` |
| `translation A B` | `{"about":A,"op":"translation"} → B` |
| `pro C B` / `con C B` | `{"about":C,"op":"pro"}` / `{"about":C,"op":"con"} → B` |
| `question B Q` | `{"about":B,"op":"question"} → Q` |
| `answer B Q A` | `{"cid_from":{"about":B,"op":"question"},"cid_to":Q,"op":"answer"} → A` |
| `author B P` | `{"about":B,"op":"author"} → P` |
| `same P1 P2` | `{"about":P1,"op":"same"} → P2` |
| `update A B C` | `{"cid_from":A,"cid_to":B,"op":"update"} → C` |
| `update-file B C` | `{"about":B,"op":"update"} → C` |
| `claimed-at X T` | `{"about":X,"op":"claimed_at"} → T`, T an RFC 3339 timestamp published as a file |

A record shown in source or target position means the CID of its canonical bytes. `answer`'s source nests: the inner question record resolves to its own CID first, then the outer record is serialized.

The edge address is `derive {cid_from: A, cid_to: B}` and the cyberlink's derived CID is `derive {cid_from: A, cid_to: B, signer: S}` — bj002's two special cases, which are just records here. The first is byte-identical to the link file itself (3.1); both are published under `particles/` by every writer that mints them — the link writer publishes the pair and the triple (3.1), and `confirm A B` / `deny A B` mint the pair as their target — so the CID a `confirm` or `deny` targets, in either arity, is always a published preimage.

Reading these edges back means dereferencing the source CID in `particles/`. An operand's CID appears as a literal string in every record that names it, so a text search narrows candidate files — but a search MUST only narrow: every surviving file is read, hashed back to its name, and parsed exactly as it would have been. A file that merely quotes a CID in prose is found by the search and dropped by the reading.

Repeats, confirms and denies are separate signals and MUST NOT be summed by a format-level reader. Summing is a reading policy and belongs to the reader.

## 5. Seal procedure

A seal is one signing moment over the whole graph home. The proof layer is rooted **at the graph home**, not at the git root: every manifest `filepath`, and therefore every leaf hash and every root, is relative to `cybergraph/` — which is why a certificate's `leaf.filepath` reads `<signer-cid>/<edge-cid>.json` with no `cybergraph/` prefix. That the path enters the signed root is also what binds each pair to its signer (3.1). Normative order:

1. Refuse if no pubkey is registered.
2. Read and validate **every** link record (3.1) — walking the signer directories, CID-v0-named directories at the root — and check that whatever stands at each certificate path is the frozen proof for that exact leaf. Refuse before anything is staged or mutated: a seal is where a file crosses from junk on disk to a statement signed by this signer.
3. `git add` the non-empty ones of the signer directories, `certs/` and `seals/`. This list only ever *adds*; it does not bound the manifest.
4. Run the proof layer's seal (section 7) with the content anchor **off** — signatures only.
5. Write the snapshot `seals/<root12>/` (3.4) if it does not exist yet. This MUST happen **before** step 6: freezing runs per link and can fail part-way, and a certificate naming a root whose snapshot was never written can never be verified or exported again — a re-seal does not repair it, because the retry mints a different root.
6. For every link with no certificate, extract its inclusion proof and freeze it at `certs/<signer-cid>/<edge-cid>.cert.json`.

**A repeated seal is not a no-op.** `seals/` is staged, so each seal catalogues the snapshots of every seal before it — the manifest differs, so the root differs, so another snapshot directory appears. Measured over five consecutive seals with nothing added: five distinct roots, manifest rows 3, 10, 13, 16, 19. This is accepted with its cost, not designed; a fixpoint would need a directory named after a root computed from a tree that already contains it.

What the manifest actually covers: every git-tracked file under the graph home except `multiproofs/`, which the proof layer excludes as derived output. Consequences worth stating: a file this staging list never mentions is still sealed once the operator commits it, and the registered pubkey is **not** under the seal — it lives in `multiproofs/pubkeys/`, and its authority comes from the signature it validates, not from inclusion.

**Time semantics.** The one provable time is the OTS anchor over the *signature*: "the signer endorsed this no later than Bitcoin block N". There is deliberately **no second anchor**. Anchoring the root statement as well would date the record's bytes without saying who asserted them, and a bundle carrying both would not say which one is the time — so a reimplementation MUST anchor signatures only, and MUST NOT report a content anchor as a permanently absent field. The earliest provable bound is set by the first seal, which is why certificates freeze. Provable granularity equals seal frequency; seal on every append. A fresh stamp reads `pending` until Bitcoin confirms.

## 6. Bundle layout

A bundle is a plain directory. It needs no git, no repo, no registered key and no network to check.

Birth bundle for an authored link:

```
<bundle>/
  <signer-cid>/<edge-cid>.json               # the record, at the leaf's filepath
  <edge-cid>.cert.json                       # exactly one *.cert.json at the root
  particles/<cid>[.ext]                      # the record's two ends, where held (default)
  multiproofs/tree-root.txt                  # + tree-root.txt.<fingerprint>.sig
  multiproofs/pubkeys/*.pub                  # named <fingerprint>.pub by the reference; the name carries no authority (2.4)
  multiproofs/ots-timestamps/tree-root.<HASH8>/…   # optional; absent ⇒ timestamp reports absent
```

There MUST be exactly one `*.cert.json` at the bundle root — that is how a verifier finds the proof — and the record MUST sit at the path the certificate's `leaf.filepath` names. The seal artifacts (root statement, signatures, pubkeys, OTS bundles) live under `multiproofs/`, because everything under that prefix is excluded from the manifest and so cannot fold itself into the CID it is checking. The certificate is the one proof file at the root, which is where this layout departs from nu-multiproof's own portable shape (7); it is safe here because every leaf this format proves is a file row, whose re-derivation reads no directory.

The OTS bundle belongs to the **birth** root, not to the current one. `multiproofs/ots-timestamps/` holds one directory per seal, each with a frozen copy of the root statement it stamped: select the bundle whose frozen `tree-root.txt` carries the certificate's `root`. Copying whatever `multiproofs/` holds at export time instead would ship a bundle claiming a time bound the certificate never earned.

Attaching the ends' particle files is the default: without them a recipient has the *address* of the instruction a link states but not its preimage, and can only decode the edge by scanning other repos. Dropping them leaves the record and certificate alone.

## 7. Proof layer — normative by reference

The merkle and timestamp layer is [nu-multiproof](https://codeberg.org/nushell-prophet/nu-multiproof/), and this spec does not restate it. A reimplementation needs, from that project's `README.md`:

- **"Content manifest"** — `multiproofs/tree-hashes.csv`: one row per git-tracked file, per parent directory, and one `.` row; columns `filepath`, `content_sha256`, `content_git`, `content_cid`; rows under `multiproofs/` excluded.
- **"Tree specification"** — leaf ordering and charsets, leaf bytes (the four parsed field values joined with `\n`), RFC 6962 domain separation (`sha256(0x00 ++ leaf)`, `sha256(0x01 ++ left ++ right)`), the MTH split shape, proof-step encoding, and the root statement: exactly `multiproof-merkle-v1 <64 lowercase hex>` plus one trailing `\n`.
- **"Bundle contract"** — the OTS bundle grammar `<stem>.<HASH8>/`, including `<stem>.<ext>.<fingerprint>.ots`, the anchor over a signature that this format's time claim rests on.
- **"Verifying without the origin repo"** — the portable layout section 6 follows, except for the certificate's position (6). Its `--bundle` enumeration rule does not bite in this format, whose leaves are always file rows, but a reimplementation that ever proves a directory row needs it.
- **"Merkle inclusion proofs"** — the `content_verified` states, of which only `true` passes; a verifier SHOULD treat any non-boolean value as a divergence rather than enumerate them, so a state added upstream cannot drift out of sync. Its `manifest_root` cross-check applies to a repo, not to a bundle, which carries no manifest and reports `null`.
- **"Dating the endorsement"** — `absent`/`pending`/`anchored`, the Bitcoin height, the rule that the **earliest** anchor of the same bytes is the reported one, and that a stamp is matched to its signer by hashing the signature file rather than by its name.
- **the `seal` pipeline** (Quick start, "Sealing under an explicit key") — the order manifest → root statement → signature → stamp, the `<file>.<fingerprint>.sig` naming rule, and that the key must be registered before it can sign.

Four things this format fixes on top of it: the content anchor is always off (5), the per-seal snapshot directory `seals/<root12>/` (3.4), the freeze rule for birth certificates (3.3), and the single inclusion proof moved to the bundle root as `<edge-cid>.cert.json` (6).

## 8. Verification

One checker, and every entry point reduces to it: a certificate, the content root its leaf resolves against, and the artifacts of the seal that certificate belongs to. A bundle answers all three by itself — one `*.cert.json` at its root, the leaf at its manifest path, the seal snapshot and pubkeys under `multiproofs/` — and `verify-bundle <dir>` is that case. Verifying in the repo names the same three instead: `certs/<signer>/<edge>.cert.json`, the graph home, and `seals/<root12>/`. The repo entry point takes the EDGE address — `verify <edge-cid> [--signer]` — and runs this checker once per copy held: each signer directory holding the edge against that signer's own certificate, plus each imported bundle carrying it; one row per copy. It deliberately does not take the cyberlink CID: the two kinds of CID can only be told apart by trying, and a guessed argument fails silently — a caller holding a link CID dereferences `particles/<link-cid>` first (3.1). Same checker, same verdict, so "verifies here" always means "verifies anywhere".

An implementation MUST NOT fold a birth certificate against the repository's *current* root statement. The graph home's `multiproofs/tree-root.txt` moves with every seal; a certificate is frozen at birth, so the two agree only for links born in the newest seal. The seal's own snapshot under `seals/<root12>/` is the artifact to check against (3.3).

Order matters — an implementation MUST NOT reach a later check with data an earlier one has not cleared.

1. **Locate the proof.** Exactly one `*.cert.json` at the root, else refuse.
2. **Canonical pubkeys.** Every `multiproofs/pubkeys/*.pub` MUST be canonical (2.4), compared as **bytes**, not as decoded text — decoding strips a UTF-8 BOM, and `EF BB BF` + a canonical line addresses to a different CID.
3. **Merkle verification.** Fold the proof to the root in the signed statement; check the SSH signatures over that statement; re-derive the leaf's content commitment. The content leg answers with a state, and only `true` passes — `missing`, `symlink`, `outside`, `directory` and `unverifiable` each block validity.
4. **Record self-addressing.** Read the record at `leaf.filepath` under both rules of 3.1, and require the CID v0 *form* of its signer directory — the parent half of the leaf path. Tampered bytes never reach the binding check.
5. **Signer binding.** The signer named by the leaf's path MUST be the CID of a pubkey that *validly signed the root statement*. Both sides of this match are key material. Matching a pubkey by filename is a hole: filing a victim's key as `<attacker-fingerprint>.pub`, with the attacker's own key beside it under any other name, binds the attacker's signature to the victim's signer CID and the bundle reads as the victim's authorship. This is also the check that gives the signer directory its authority: the path is inside the signed root (5), so a pair refiled under another signer's directory names a signer who never signed that root — or changes the leaf path and breaks the proof outright.
6. **Endorsement time.** Report the anchor over *that signer's* signature, matched through the same pubkey table. One signer may hold several signature files, so rank all of that signer's rows: an `anchored` row wins, and among those the **lowest** Bitcoin block, since the claim is "no later than T"; failing that a `pending` row, which MUST NOT be ranked together with `absent`; failing that `absent`, meaning the endorsement is real but undated. A signer with no valid signature has no endorsement at all, which is a different answer from an undated one.

The verdict is a record, not a boolean. `valid` is the conjunction of the merkle verdict and the signer binding. Malformed input (no certificate, a non-canonical pubkey) raises; a cryptographic or content mismatch returns `valid: false` with the first failing reason.

## 9. Conformance vectors

Verified against the reference implementation on 2026-08-18 (`nu toolkit.nu test` — 156 passed).

**Link record and derived CIDs** (`tests/test_record.nu`, `tests/test_convention.nu`):

```
A = QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV
B = Qmc9pm5gQqDwJMiFTmFEuTxRhSy5Cn2yt7NZh1LrxmMhSi
S = QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr
```

| bytes (plus one trailing `\n`) | CID v0 |
|---|---|
| `{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"}` | `QmUiARbMPT9WNXqvgb2BB9gWFXRiCEqD96AF5xebwNTCTT` |
| `{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","signer":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}` | `QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze` |
| `{"op":"confirm"}` | `QmcLFo8UMWWuUP7ruztAW5C1zPwmF7GTZs8X6Lig4pXkBh` |
| `{"op":"deny"}` | `QmU8kL28M7yecZ5iPGJZ3e89fytWFzLszU3QtKRj5hV2kK` |
| `{"op":"agree"}` | `QmTswdDR4inURY4GeWGvmL9S8xrDZjfiGEyeUUZzUNRNYk` |
| `{"op":"disagree"}` | `QmbQUXxqMrFA6zGYmgjvbFKyywS7Gcbb3afb3wqG6s7r6J` |
| `{"cid_from":A,"cid_to":B}` (the edge address) | `QmawrHuBDdcSRCPumzsKfsMi5FJne8xai9WNPAdr3NmLBV` |
| `{"cid_from":A,"cid_to":B,"signer":S}` (the cyberlink) | `Qme4L2P7QwNoijw6HzYVrqrrtk99oj1XvJHvAb9yobHVLe` |

The first row is a link file's bytes — the pair; its CID is the filename stem in the signer's directory. The second row is the same act's triple — the particle the writer publishes, whose CID is the cyberlink's derived address. Reproduce any row with `printf '<bytes>\n' | ipfs add --only-hash --cid-version=0`.

**Signer identity.** The canonical form and the fingerprint are pinned by nu-multiproof (`nu-multiproof/pubkey.nu`'s `@example`, `tests/test_allowed-signers.nu`; the canonicalization itself in `tests/test_pubkey.nu`). The signer CID is the row that couples 2.1 to 2.4 to 3.1 to the binding in 8.5:

```
line        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf
canonical   the same line plus "\n" — 81 bytes
fingerprint b610a91de8fa99e224f6b2e7fb6bb8c9e8f0303f8d72d14e5a494ab8d1c68011
signer CID  QmSxVNMd5zcxuoQ7TjgngUECWGSj4XCwK6oAQqwirUN9rx
```

**CID v0.** The table above exercises only the single-leaf path — every record in it is far under one chunk, so it cannot catch a mistake in the fold. These five exercise the rest. Let **P** be the 16 bytes `00 01 02 … 0f` repeated 16384 times, which is exactly one 262144-byte chunk.

| content | CID v0 | what it pins |
|---|---|---|
| the empty file, 0 bytes | `QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH` | the omitted Data field, and that `filesize = 0` is emitted anyway |
| 262144 zero bytes | `QmRk1rduJvo5DfEYAaLobS2za9tDszk35hzaNSDCJ74DA7` | the chunk boundary — one leaf, not two |
| P ‖ P ‖ the first 1000 bytes of P | `QmWRgwTqCcE11Fs9rKviA8uxnACY5VWAyEJsCU44gD33ue` | one branch over three leaves: link order, Tsize, and blocksizes carrying filesizes |
| P repeated 175 times | `QmazZG2Fp65Los6G7GUjNgtSiJ9xxixYKNop6frmWR1QkK` | the 174-wide fold, and therefore a second level |
| the empty directory | `QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn` | a directory node with no links |

All five are recorded from the reference IPFS client (nu-multiproof `tests/test_cid-v0.nu`), which also holds directory-tree and shard-boundary vectors. An implementation that reproduces these and the first row of the record table has exercised every branch of 2.1 except a file DAG deeper than two levels (~7.9 GB), which nothing outside that repo pins.

## 10. Deliberately not specified

- **Custody, handoff and import.** Taking another signer's bundle, keeping it read-only, and re-exporting it with a signed chain of custody layers is a separate subsystem, described in `README.md` ("Bundles, import, provenance"). Two of its consequences reach the path specified here. A birth bundle exported with a named recipient carries `<edge-cid>.handoff.json` and its signature **at the bundle root**, and the reference verifier folds that check into `valid` — so a bundle carrying one falls outside the verdict of section 8, which has no step for it. And a graph that has imported something stages `imported/` and `receipts/` into its seal as well, putting more rows in the manifest and so minting a different root; a graph that never imports has neither directory, so its manifest is unaffected.
- **Reading policy.** How to weigh repeats against confirms and denies, whose signature counts, how time decays — bj002 leaves this as `f(repeats, confirms, denies, signer_weights, time_decay)` and so does this format. A reader that sums them is making a policy choice, not implementing this spec.
- **Human names for keys.** Nothing here stores a label for a key anywhere. A `.pub` filename is decoration.
- **A provable lower time bound.** OTS bounds time from above only. "Created no earlier than" would need a recent unpredictable value inside the signed bytes.
- **Cross-signer aggregation.** A graph home is one signer's own record. A bundle received from another signer is that signer's copy, verified against its own birth seal; mixing the two would silently turn "what this signer said" into "what everyone said".
- **Retrieval.** CIDs name content, they do not publish it. Nothing here talks to an IPFS network.

## 11. Known limits

- Deriving content time through the signature inherits every way SSH verification can rot over decades, where a content anchor would stay a bare sha256 compare. That trade is taken knowingly (5).
- The reference implementation is a proof of concept, agent-written and never reviewed by an outside cryptographer.
