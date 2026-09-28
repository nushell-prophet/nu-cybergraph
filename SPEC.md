# Cybergraph format specification v1

What an independent implementation, in any language, needs in order to write and read the same artifacts as `nu-cybergraph`:
the byte formats, the folder structure, the key format, and the procedures that produce and check them.

This document pins mechanics only.
Reasons live in `README.md`;
the concept lives in `bostrom-journal` bj002 and bj003.
Where the two disagree with the code,
the code and its golden tests win,
and the divergence is a bug in the prose.

**Pre-1.0.** There is no backwards compatibility to keep.
Any change to section 2 or 3 recomputes every CID in every graph
and is a format version bump, not an edit.

MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Terms

| term | meaning |
|---|---|
| particle | a file whose CID stands in an edge: one name for the vertex of the graph and the bytes under that CID, the carrier of meaning (bj001: a file becomes a particle of the cybergraph when its CID stands in an edge); the store and the `particle` commands say particle for any published file, since a file is published to be named |
| vertex | the same particle in graph-theory words: its place in the graph, apart from its bytes |
| edge | the pair `{cid_from, cid_to}` — the unit of the operational layer; one address shared by every signer asserting it |
| link, cyberlink | an edge asserted by one signer — the triple; its file holds the pair, the signer lives in the path |
| signer | an identity: the CID v0 of an SSH public key file in canonical form |
| graph home | `<git-root>/cybergraph/` — one signer's whole graph |
| seal | one signing moment: manifest → merkle root → SSH signature → OTS stamp |
| birth certificate | the inclusion proof from the first seal that catalogued a link, frozen |
| bundle | a directory holding everything needed to verify one link with no origin repo |

## 2. Primitives

### 2.1 CID v0

Every address in this format is a CID v0 of concrete bytes:
base58btc, always `Qm` followed by 44 characters.

```
^Qm[1-9A-HJ-NP-Za-km-z]{44}$
```

It is IPFS UnixFS over DAG-PB,
and equals what the reference client reports for `ipfs add --only-hash --quieter --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144`.
The construction is written out below
so that no IPFS library is needed.

**Constants.** Payload chunk size 262144 bytes.
Links per intermediate node 174 (go-unixfs `DefaultLinksPerBlock`: an 8 KiB block target over ~47 bytes per link).
Directory shard threshold 262144,
each entry estimated as its name length plus 34.

**Varint** is unsigned LEB128:
while the value is 128 or more, emit `(value mod 128) | 0x80` and divide the value by 128;
then emit what remains.
Negative values have no encoding
and MUST be refused rather than two's-complemented.

**Protobuf framing.** A length-delimited field is `<tag byte><length varint><bytes>`.
Only these fields appear,
and they are emitted in the order listed:

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

Besides its digest, a node carries two numbers:
**Tsize**, the serialized length of its own block plus the Tsize of every node beneath it,
and **filesize**, the payload bytes it covers (file nodes only).

**Leaf node** — one chunk of payload.
Its UnixFS message is Type = 2, then Data = the chunk, then filesize = the chunk length.
An **empty file omits the Data field entirely**
— it does not carry a zero-length one —
but still emits `filesize = 0`:
Data is the only conditional field,
and protobuf's habit of dropping default-valued scalars does not apply here.
The block is that message wrapped as PBNode.Data, with no links.

**Balanced fold.** Split the payload into 262144-byte chunks in order and make each a leaf node;
an empty payload gives exactly one leaf over zero bytes.
Then, while more than one node remains,
take the nodes in order,
cut them into consecutive batches of 174,
and replace each batch with a branch node over it.

**Branch node.** The block is its children's links in order
— each `PBLink` with an empty Name —
followed by PBNode.Data holding UnixFS Type = 2, filesize = the sum of the children's filesizes, and one blocksizes entry per child in link order.
Each blocksizes entry is that child's **filesize**
— the payload bytes it covers —
and not the size of its block, which the field's name invites.
A branch carries no UnixFS Data field.

**Directory node.** The block is one PBLink per entry,
Name being the entry name,
sorted **byte-wise by name**
— link order is part of what the CID commits to —
followed by PBNode.Data holding UnixFS Type = 1 and nothing else.
If the sum over entries of (byte length of the name + 34) exceeds 262144,
IPFS switches that directory to a HAMT shard whose CID this construction does not reproduce:
refuse it, rather than emit a basic-directory CID no IPFS client agrees with.

**The CID.** Take sha2-256 of the serialized block,
prefix `0x12 0x20` (multihash: sha2-256, 32 bytes),
and base58btc-encode the resulting 34 bytes with the alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`,
emitting one leading `1` per leading zero byte.
That prefix is constant,
which is why every CID v0 renders as `Qm` plus 44 characters.

Directory CIDs are needed only by the manifest layer (7).
Reference implementation: nu-multiproof `nu-multiproof/_cid-helpers.nu`;
vectors in 9.

### 2.2 Canonical record bytes

One serialization rule covers every record this format hashes
— link records and derived records alike.

- The record MUST be flat,
  and every value MUST be a string.
  A reference to another record is that record's CID, never a nested object.
- Keys are sorted by the byte order of their UTF-8 bytes:
  locale-free, case-sensitive.
- Compact JSON — no whitespace anywhere outside string values.
- Exactly one trailing `\n`.

A **derived CID** is the CID v0 of those bytes.
Reproduce any of them with `printf '<record>\n' | ipfs add --only-hash --cid-version=0`.

All values used in practice are CIDs and reserved `op` words,
whose charsets contain nothing JSON escapes,
so the bytes are reproducible without an escaping policy.

### 2.3 Field types

| type | rule |
|---|---|
| CID | `^Qm[1-9A-HJ-NP-Za-km-z]{44}$` |
| timestamp | `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z\|[+-]\d{2}:\d{2})$` — RFC 3339, fractional seconds optional |
| hash | `^[0-9a-f]{64}$` — sha256, lowercase hex |

Validation is by exact key set:
a record with an unknown or missing key MUST be refused before any value is read.

### 2.4 Signer identity — the key format

A signer is the **CID v0 of its public key file bytes**,
and those bytes have exactly one legal form:

```
<type> <base64>\n
```

No comment, no leading or trailing whitespace, no second line, no BOM.
The key comment is excluded deliberately:
it is mutable metadata,
and keeping it would fork one key into several identities.

`<type>` MUST be one of:

```
ssh-rsa  ssh-ed25519
ecdsa-sha2-nistp256  ecdsa-sha2-nistp384  ecdsa-sha2-nistp521
sk-ssh-ed25519@openssh.com  sk-ecdsa-sha2-nistp256@openssh.com
```

Certificates (`*-cert-v01@openssh.com`) are refused.
`ssh-dss` is refused:
OpenSSH 10 removed DSA,
so such a key could never be verified.

`<base64>` MUST be the encoding OpenSSH itself writes for that key.
Checking the type prefix is not enough
— RFC 4251 permits a redundant leading zero byte in an RSA mpint,
and OpenSSH trims it while parsing,
so a padded copy of a key loads fine, reports the same fingerprint, and addresses to a *different* CID.
The reference implementation settles this by round-tripping the line through `ssh-keygen -e -m RFC4716` and `ssh-keygen -i -m RFC4716` and requiring a fixed point.
An implementation MUST make an equivalent check;
accepting the bytes as given hands one key a second identity.

Canonicalization is enforced at exactly two boundaries:
registration, and every read of a bundle's `multiproofs/pubkeys/` at verification
— including a bundle built from this repo's own key,
so the registered key is re-checked whenever an own link is verified.
A key is never re-checked *in place*,
so one that reached a trust list by any other route keeps whatever bytes it has,
and its CID identity differs from the same key stored through registration.

Two derived names, not to be confused:

| name | value | used for |
|---|---|---|
| signer CID | CID v0 of the canonical file bytes | the signer directory a link file lives in; the `signer` field of the triple record; the signer binding at verification |
| fingerprint | sha256 of the base64-decoded key blob, lowercase hex | the pubkey filename, the middle segment of a `.sig` filename, nu-multiproof's principal |

A pubkey file's **name is decoration**.
Identity comes from the bytes inside it.
A verifier MUST NOT match a signer CID by filename
— hash the file contents and compare.

A graph home has exactly one **authoring** identity,
while `multiproofs/pubkeys/` MAY hold several keys
— the two are different questions.
The directory is nu-multiproof's trust list
— the keys whose signatures this format accepts —
and verification reads every valid signature over a root (8),
so a key registered beside the authoring one can add a signature but never take authorship.
The authoring identity is the key the checkout itself signs with
— `user.signingKey` in its git config, the same key `seal` signs the root with —
because a record's signer MUST be a key that validly signed the root cataloguing it (8)
or the binding fails.
An implementation MUST resolve it by key material:
the canonical form of the configured key equals a registered file's bytes, never a filename match.
The reference implementation refuses to write when no key is configured at all, when the configured key is not registered, and when nothing is registered
— a single registered key is not an answer either,
since the trust list is exactly where a key belonging to someone else is meant to sit.
A command with an operator-facing `--key` (export) resolves that key instead of the config.
Registration stays deliberate:
`init` establishes the identity and MUST NOT grow a trust list that already holds one, undoing what such a run added
— a trust list states whose signatures a graph accepts,
so a key must never join it by accident.
A key joins beside the identity only by an explicit route,
`init --co-signer <key>.pub` in the reference implementation,
which registers and establishes nothing.
`seal` refuses only the zero case.

### 2.5 SSH signatures

Every signature in this format is a detached SSH signature (SSHSIG) over a file's exact bytes,
made and verified under the namespace **`file`**
— one fixed value, never a caller's choice.
SSHSIG puts the namespace inside the signed preimage,
so this is not cosmetic:
a verifier using any other value rejects every good signature.
It is fixed rather than configurable
because the value is interpolated into the rendered trust list,
where a crafted namespace injects `cert-authority` and makes every registered key trusted for anything.

Domain separation therefore has to live in the signed bytes.
That is why the root statement is a single line opening with the token `multiproof-merkle-v4` (7) rather than a bare hash.

A signature sits beside the file it signs,
named `<file>.<fingerprint>.sig`.
Verification renders its trust list from the proof directory's own `multiproofs/pubkeys/`,
one line per key: `<fingerprint> namespaces="file" <type> <base64>`.

## 3. Repository layout

The graph home is always `<git-root>/cybergraph/`.
A particle referenced by a link need not have its bytes there, or in the repo at all
— links name CIDs, not paths.

```
cybergraph/
  <signer-cid>/<edge-cid>.json              # link records: pair in the file, signer in the path  3.1
  particles/<cid>[.ext]                     # the particle store, self-addressed                  3.2
  certs/<signer-cid>/<edge-cid>.cert.json   # frozen birth certificates, mirroring the layout     3.3
  order/<signer-cid>/<edge-cid>.order.json  # the act's place in the signer's run (+ .order.cert.json)   3.5
  seals/<root-hex-12>/                      # per-seal root statement + signatures                3.4
  exports/<signer-cid>/<edge-cid>/          # bundles this repo built                             6
  imported/<signer-cid>/<edge-cid>/         # bundles landed from others, read-only               10
  receipts/<author-cid>/<edge-cid>.receipt.json   # custody receipts (+ .receipt.cert.json)       10
  multiproofs/pubkeys/<fingerprint>.pub     # the registered key, canonical bytes                 2.4
  multiproofs/                              # the rest of the proof layer                         7
```

Signer directories sit at the graph root
and are told from the reserved directories by form alone:
a directory named by a CID v0 is a signer's,
and the reserved names never match that pattern.

**The tree above is closed.**
It is the whole set of what may exist under the graph home,
and an implementation MUST refuse anything else there rather than ignore it
— a hand-written `README.md` or `.gitignore` at `cybergraph/` included,
because a seal signs whatever is committed under the graph home,
and what a signer has not checked they must not be made to attest.
Anything written by hand belongs beside the graph home, not inside it.
`multiproofs/` is the one directory named here and governed elsewhere:
it is the proof layer's (section 7),
so an implementation recognises it and does not police its contents.
Nor does the rule reach inside a bundle under `exports/` or `imported/`,
which is one artifact checked as a whole (section 8),
or inside a seal snapshot, which the proof layer owns.

Two refusals carry it, and they answer different questions.
A reader MUST refuse a graph home whose **top level** it does not recognise,
rather than report the graph as empty:
a reader that cannot tell a foreign layout from an empty one turns a silent
misread into every count, tally and walkthrough built on it.
A seal MUST refuse on the **whole** closed set (5), because it is the moment those bytes get signed.
The pubkey filename is the reference implementation's choice and carries no authority
— see 2.4.

The signer directories, `certs/`, `order/` and `seals/` are what a seal stages into git;
`particles/` and `exports/` are not staged by the seal (see 5)
— but a store file the graph reaches has to be in the index before the seal,
and the seal refuses while it is not.

A sha256 git backend (`git init --object-format=sha256`) is recommended.
The format works on sha1 repos too.

### 3.1 Link record — `<signer-cid>/<edge-cid>.json`

The atomic edge, in its signer's directory.
The file holds exactly the pair, two keys, both CIDs, nothing else:

```json
{"cid_from":"Qm…","cid_to":"Qm…"}
```

- Serialized by the canonical rule (2.2),
  so key order is alphabetical — `cid_from`, `cid_to` — compact, one trailing `\n`.
- The filename stem MUST be the CID v0 of the file's exact bytes
  — the **edge address**, `derive {cid_from, cid_to}` under 2.2.
  Two signers stating one edge share one filename, each in their own directory.
- The signer is **not in the bytes**:
  it is the directory name, which MUST be a CID v0.
  What binds the pair to the signer is the seal
  — the path enters the signed root (5) —
  so a file moved into another signer's directory breaks its own proof.
  A reader checks the directory's *form* only;
  the binding is checked at verification (8).
- There is **no timestamp**.
  A time inside the record would fork one act into a different CID per recording moment.
  Provable time comes from the seal (5);
  a claimed time is an ordinary edge (`claimed-at`, section 4).

The cyberlink — the triple `derive {cid_from, cid_to, signer}` — is computed, not stored:
pair from the file, signer from the path.
It is not the file's name.

**Neither address is published by the writer.** A writer MUST NOT publish the pair or the triple as a store file when it writes the link.
The store holds bytes a writer decided to put there,
never bytes a command derived on the way:
writing a link points at its two endpoints and at nothing else.
So `link add` publishes what its endpoints resolve to, and no more.

A derived address becomes dereferenceable when an act names it,
and publishing the preimage is part of making that act
— the same rule section 4 puts on every record a convention mints.
`confirm-edge A B` / `deny-edge A B` mint the pair as their target and publish it;
`confirm-link A B S` / `deny-link A B S` do the same for the triple;
naming either in a plain link means publishing it first (`particle add-edge` / `particle add-link`, 3.2).
Publishing is idempotent,
so a second signer of the same edge and a convention minting the same pair write nothing new.

An implementation MUST NOT close this gap by resolving a derived CID out of the link file that holds the same bytes.
The bytes are there and the resolution would work,
but it costs a second index beside the store,
and it puts a preimage where nothing pointed at one.

A reader MUST enforce both addressing rules,
from a **single** read of the bytes:

1. CID v0 of the raw bytes equals the filename stem.
2. Those raw bytes equal the canonical serialization of the parsed record.

Rule 2 is not redundant.
Reordered keys, added whitespace, or a duplicate key each hash to some other CID
and would pass rule 1 under that name
— giving one act two addresses.
Decode as UTF-8 explicitly;
guessing the encoding lets a UTF-16 file parse to the same pair under a different CID.

**Triple guard.** The path IS the triple
— signer in the directory, edge in the filename —
so a repeat of the same act lands on the same path,
and a writer MUST return the existing record rather than write a second file.
One act, one file.
The no-op still re-reads and re-checks the file on disk first,
so a corrupted record fails loudly instead of reading as a successful repeat.

### 3.2 Particle store — `particles/<cid>[.ext]`

Arbitrary content published as a self-addressed file, storing the exact bytes:
no newline appended, no encoding transform.

- The address is always the bare 46-character CID.
  An extension is a presentation hint only (a forge renders `.md`),
  matching `^[A-Za-z0-9]+(\.[A-Za-z0-9]+)*$`.
- One CID, one file.
  Re-adding existing content under a different extension is a no-op
  — the first name wins.
  A store holding two files for one CID is broken
  and MUST fail fast on read, never silently pick one.
- A reader MUST hash the bytes back to the CID before serving them.
- Absence is ordinary for a reader:
  a link names CIDs and the bytes need not be local.
  Absence and tampering MUST stay distinguishable
  — an optional read returns nothing for a CID the store does not hold,
  and still raises for a file that fails its hash.

The store holds content published by a user,
and the instruction and address records minted by conventions (section 4)
or published deliberately (`particle add-edge`, `particle add-link`) so a later act can name them.
Publishing a derived record is what makes a derived CID readable
— the record is its own preimage —
and it is a decision a writer makes, never a side effect of computing an address (3.1).
A preimage MAY therefore sit in the store before anything names it
— the writer publishes it for a reference they are about to make.

A canonical record's preimage MUST be publishable through the implementation's own serializer.
Hand-writing one is not an alternative:
any byte string other than the canonical form (2.2) hashes to a different CID,
and both files are self-addressed, so nothing reports the mistake.

That publisher's operands are admitted by the same rule as every other write command's:
a CID must resolve to bytes this repo holds, unless the caller says otherwise;
anything else is content, published first and named by its CID.
One record MUST NOT have two admission rules
— a convention minting a pair as its target and a caller publishing that same pair directly are the same record,
and which command wrote it cannot decide what got in.

Store files are not sealed directly.
A file is time-anchored the moment a sealed link names its CID,
because showing bytes that hash to an anchored CID extends the anchor to those bytes.

They still have to be committed, and before the seal, not after.
The manifest is git-tracked files (section 5),
so a store file outside the index enters no root
— the anchor above reaches its bytes only for whoever already holds them.
A file is **reachable** when a link in this graph names its CID:
as `cid_from`, `cid_to` or `signer`,
as the pair or triple record derived from a link, once someone published that preimage (3.1),
or as an operand inside a record reached that way (section 4),
applied until nothing new appears.
A store file that is reachable by none of those is published and linked to nothing,
and only its publisher can say whether that was the intent.

### 3.3 Birth certificate — `certs/<signer-cid>/<edge-cid>.cert.json`

The inclusion proof extracted from the **first** seal that catalogued the link,
frozen forever,
filed mirroring the link layout — the signer's directory, the edge's name.
JSON, 2-space indent (the bytes are not addressed, so formatting is free):

```json
{
  "schema": "multiproof-merkle-v4",
  "leaf": {
    "filepath": "<signer-cid>/<edge-cid>.json",
    "content_sha256": "<64 hex>",
    "content_git_sha1": "<40 hex>",
    "content_git_sha256": "<64 hex>",
    "content_cid": "<Qm…>"
  },
  "path": [ {"side": "left|right", "hash": "<64 hex>"} ],
  "root": "<64 hex>"
}
```

`path` is leaf-to-root order and `side` names the **sibling**'s position.
`root` is self-description only
— a verifier folds to the root in the *signed statement*, never to this copy.

**Never regenerated.** Its OTS anchor is the link's earliest provable time bound;
later seals only mint newer roots.
`verify` and `bundle` MUST use the birth seal, never the repo's current root.

Whatever stands at a certificate path MUST be that certificate.
Deciding "already certified" from bare file existence is not enough:
a directory, an empty file, or a genuine proof whose `leaf.filepath` names a different link each leave the link uncertified while it is catalogued,
so the certificate a later seal writes names a later root than the link's birth.
The reference implementation runs this check at seal time only
— `verify` and `bundle` still branch on bare existence,
so junk at a certificate path reaches them as a crash rather than a verdict.

The same freeze rule governs a second proof, and the check above covers both.
A link's position (3.5) freezes at `order/<signer-cid>/<edge-cid>.order.cert.json`,
under the first seal that catalogues the number
— never regenerated, for the same reason:
what makes a number provable is the root it entered,
and a later seal would move that root while the run reads unchanged.

### 3.4 Seal snapshot — `seals/<root-hex-12>/`

The directory name is the first 12 characters of the seal's merkle root hex.
It holds that seal's root statement and its signatures,
copied out of `multiproofs/` before the next seal overwrites them:

```
seals/<root12>/tree-root.txt
seals/<root12>/tree-root.txt.<fingerprint>.sig   # and/or the bare tree-root.txt.sig
```

This is what makes a frozen certificate exportable:
certificates verify against the root they were born under,
and `multiproofs/tree-root.txt` is overwritten every seal.

The snapshots are also the only place the run of seals can be read:
a statement names its own `seq` and the root it supersedes (7),
while `multiproofs/` keeps just the live one.
An implementation MUST read them in order and refuse a gap
— `seq` running 0..N, each `prev` the root before it —
instead of reporting a shorter chain,
because a missing snapshot is every certificate born under that root verifying against nothing.

### 3.5 Link position — `order/<signer-cid>/<edge-cid>.order.json`

The act's place in its signer's run, filed mirroring the link layout.
JSON, exactly one key, and the key *is* the state (the bytes are not addressed, so formatting is free):

```json
{"added_at": "2026-08-31T09:41:12+00:00"}
```

```json
{"seq": "42"}
```

`added_at` while the position is provisional, `seq` once a seal has numbered it
— never both keys, and never one key holding the other's value.
An implementation validates by exact key set and refuses everything else,
so nothing has to infer the state from whether a proof lies beside the file.

`added_at` is the `timestamp` type of 2.3, narrowed to UTC
— the zone offset MUST be `Z` or `+00:00`, and a time in any other offset MUST be refused,
both when the position is written and when it is read.
Nothing signs a claimed time, so it is only worth reading if two files stating one instant state it one way.
`seq` is a decimal count with no leading zeros starting at 0
— the root statement's own rule for its own counter (7), not a second convention.
The file states **only** its one key:
a certificate names the root it folds to, so it cannot sit inside the tree that produces that root,
and a position must,
so which seal minted the number is answered by the proof it verifies against, exactly as for a link record.

What the number is for is not indexing.
A run with no gaps makes a signer's record provably complete,
so a replica cannot be silently thinned
— the property a per-feed counter gives an append-only log.
Everything below follows from that one purpose.

- **The run is per signer directory.** A graph home holding several signer directories holds several runs, each numbered from 0.
- **A writer writes the time, never a number**, on the same branch that writes the record.
  Numbering needs a moment that sees the whole run at once, and a writer is not one:
  the seal is (5).
  A repeat of the same act (3.1's triple guard) writes neither file.
- **The seal turns the time into a number** (5), and that is the only place a `seq` comes from.
  The provisional value is a time and not a counter because two runs have to be mergeable:
  two checkouts counting 42, 43, 44 each could be joined only by putting one run wholly before the other,
  which is not the order the acts happened in,
  while times interleave and recover the order that actually held.
  What that costs is clock skew between machines instead of colliding counters
  — the better failure of the two, because it degrades the order without duplicating anything.
- **Provisional until numbered.** A position stating `added_at` MAY be rewritten by the next seal;
  one stating `seq` MUST NOT move.
  That is the rule the record itself lives by — a file on disk until a seal signs it —
  and it is what lets two checkouts be merged at all (5).
  A claimed time enters the graph home but never a root:
  the seal replaces it before staging, so no signature covers it and the graph attests no times.
  A proof folding to a root over a position that still states `added_at` is therefore not a position in any state, and MUST be refused.
- **A link that never reaches a seal keeps its time and never gets a number.**
  That is honest rather than a gap: nothing about an unsealed link is provable, its record included.
- **The bijection is a seal-time refusal** (5): every link record has exactly one position, and every position names a link record.
  Without both halves the number does nothing it exists for:
  a signer could seal a link and simply not number it,
  and a reader holding the entire graph would see a contiguous run beside an unnumbered link.
- A position is verified by folding its own proof, the same machinery as a record's,
  and the leaf path is what binds the number to the signer whose run it is.
  The verdict is reported **beside** section 8's, never folded into `valid`:
  what the number states is a fact about the run, not about whether the act is proven,
  and a reader weighing completeness has to see the two apart.
- A backfilled position — one written for a link that predates the run — freezes under a LATER root than its link's birth certificate.
  A bundle carries that seal beside the birth one (6),
  so such a bundle rests on two seals rather than one.

## 4. Conventions — instructions as ordinary edges

A convention encodes an instruction for processing the graph as a plain edge whose **source** is a derived CID.
The grammar has one atom and one constructor:

- An **address expression** is a leaf (an operand) or a record whose values are themselves expressions.
- An operand is an address when it matches the CID v0 pattern of 2.3.
  Otherwise it is content:
  a string naming an existing file publishes that file's bytes,
  any other string publishes itself,
  and a path-shaped string naming nothing MUST be refused rather than published as its own text.
  So content that itself reads as a CID, or as a path, cannot be passed as content
  — publish it first and pass the CID back.
- A nested record resolves to its derived CID,
  so the final record is always flat and 2.2 applies.
- The single exception is the value of an `op` key:
  a reserved word of the format, used verbatim, never treated as an operand.

Every record passed through MUST be published as a file under `particles/`
— that is what lets a reader dereference an opaque source CID and get named fields back.

Eighteen verbs for twelve conventions
— `confirm` and `deny` are one convention each and two verbs each, one per subject.
Four verbs answer to no bj002 convention:
`repeat` is edge repetition (bj002 names it beside the conventions, not among them — it puts no special CID in the source);
`claimed-at`, `update-particle` and `translation-particle` are this format's extensions, which bj002's open set permits.

An `op` word names its subject wherever the verb has one
— `confirm_edge` / `confirm_link`, `deny_edge` / `deny_link`, `update_edge` / `update_particle`,
and, with a single possible subject, `agree_particle`, `disagree_particle`, `quote_particle`, `author_particle`, `translation_particle`, `answer_edge`.
The record shape carries the same fact,
but only for a reader that parses the record,
and a CID is opaque:
no tool can tell a particle CID from an edge address at write time unless the preimage already sits in the store.
So the word is the one check that always works
— a writer cannot put a particle verb on an edge address without the mismatch showing in the word itself.
Where a verb takes any CID on purpose the word stays bare
— `pro`, `con`, `question`, `same`, `claimed_at` —
so a bare word is the signal "any CID".
bj002 spells the same words since 2026-09-02;
the addresses still differ, because bj002 hashes a comma-join where this format derives from a record (2.2),
so no address here has ever matched one there.

| verb | edge written |
|---|---|
| `repeat A B` | `A → B` |
| `confirm-edge A B` | `{"op":"confirm_edge"} → {"cid_from":A,"cid_to":B}` |
| `confirm-link A B S` | `{"op":"confirm_link"} → {"cid_from":A,"cid_to":B,"signer":S}` |
| `deny-edge A B` | `{"op":"deny_edge"} → {"cid_from":A,"cid_to":B}` |
| `deny-link A B S` | `{"op":"deny_link"} → {"cid_from":A,"cid_to":B,"signer":S}` |
| `agree-particle B` / `disagree-particle B` | `{"op":"agree_particle"}` / `{"op":"disagree_particle"} → B` |
| `quote-particle A B` | `{"about":A,"op":"quote_particle"} → B` |
| `translation-particle A B` | `{"about":A,"op":"translation_particle"} → B` |
| `pro C B` / `con C B` | `{"about":C,"op":"pro"}` / `{"about":C,"op":"con"} → B` |
| `question B Q` | `{"about":B,"op":"question"} → Q` |
| `answer-edge B Q A` | `{"cid_from":{"about":B,"op":"question"},"cid_to":Q,"op":"answer_edge"} → A` |
| `author-particle B P` | `{"about":B,"op":"author_particle"} → P` |
| `same P1 P2` | `{"about":P1,"op":"same"} → P2` |
| `update-edge A B C` | `{"cid_from":A,"cid_to":B,"op":"update_edge"} → C` |
| `update-particle B C` | `{"about":B,"op":"update_particle"} → C` |
| `claimed-at X T` | `{"about":X,"op":"claimed_at"} → T`, T an RFC 3339 timestamp published as a file |

A record shown in source or target position means the CID of its canonical bytes.
`answer-edge`'s source nests:
the inner question record resolves to its own CID first,
then the outer record is serialized.

The edge address is `derive {cid_from: A, cid_to: B}` and the cyberlink's derived CID is `derive {cid_from: A, cid_to: B, signer: S}`
— bj002's two special cases, which are just records here.
The first is byte-identical to the link file itself (3.1),
which does not make it a store file:
the link writer publishes neither address (3.1),
and `confirm-edge A B` / `deny-edge A B` publish the pair because they mint it as their target.
So the CID any of the four confirm and deny verbs targets is always a published preimage
— published by the act that names it.

Reading these edges back means dereferencing the source CID in `particles/`.
An operand's CID appears as a literal string in every record that names it,
so a text search narrows candidate files
— but a search MUST only narrow:
every surviving file is read, hashed back to its name, and parsed exactly as it would have been.
A file that merely quotes a CID in prose is found by the search and dropped by the reading.

Repeats, confirms and denies are separate signals
and MUST NOT be summed by a format-level reader.
Summing is a reading policy and belongs to the reader.

## 5. Seal procedure

A seal is one signing moment over the whole graph home.
The proof layer is rooted **at the graph home**, not at the git root:
every manifest `filepath`, and therefore every leaf hash and every root, is relative to `cybergraph/`
— which is why a certificate's `leaf.filepath` reads `<signer-cid>/<edge-cid>.json` with no `cybergraph/` prefix.
That the path enters the signed root is also what binds each pair to its signer (3.1).
Normative order:

1. Refuse if no pubkey is registered.
1a. Refuse if anything under the graph home falls outside the closed tree of section 3.
   Step 4 stages those directories wholesale,
   so a file the layout cannot describe would enter this seal's signed manifest unvalidated
   — attested by the signer while none of the checks that make an attestation mean something apply to it.
   The recovery is to remove it or move it out, and there is no override:
   a flag to sign past an unnamed object is the thing the closed set exists to prevent.
2. Read and validate **every** link record (3.1)
   — walking the signer directories, CID-v0-named directories at the root —
   and check that whatever stands at each certificate path is the frozen proof for that exact leaf.
   The same check covers each position's proof path (3.3):
   what stands at a proof path has to *be* the proof for that exact leaf,
   or step 7 would leave a signed proof beside bytes it never covered.
   Refuse before anything is staged or mutated:
   a seal is where a file crosses from junk on disk to a statement signed by this signer.
2a. Refuse unless every link record has exactly one position and every position names a link record (3.5),
   and refuse unless each signer's **numbered** run — the positions stating `seq` — is 0..N with no gap and no repeat.
   The first is what makes a withheld link visible at all.
   The second is not repairable here and so is reported rather than fixed:
   a hole at 3 cannot be numbered away, because the numbers around it are already signed,
   so this seal would cement it instead of naming it
   — the refusal 3.4 makes about a missing snapshot, for the same reason.
   Read over what states a `seq` and not over what a proof covers:
   `seq` is what "already assigned" means,
   so a seal that died between step 3a and step 7 left numbers no proof covers,
   and handing those out a second time is how one number ends up counting two acts.
3. Refuse if any store file the graph *reaches* (3.2) is outside the git index.
   The manifest is git-tracked files,
   so such a file enters no root while the link naming it is signed and frozen
   — a certificate proving an edge whose endpoint bytes were never attested.
   An implementation MAY offer an explicit override for sealing without those bytes.
   It never reaches the store's layout rule:
   a name under `particles/` that is no address is refused by step 1a,
   which no override touches.
   Publishing is the operator's act,
   so this step refuses rather than staging on their behalf.
3a. Number the **provisional** positions — those stating `added_at` (3.5):
   sort them by that time, break ties byte-wise by edge CID (the manifest's own ordering rule, so nothing new decides it),
   assign consecutive numbers after the last one already assigned,
   and rewrite each file to state `seq` instead.
   Times are compared as times and not as strings:
   every claimed time is UTC (3.5), but `Z`, `+00:00` and fractional seconds still put one instant in several byte orders,
   and only the parse compares those correctly.
   This MUST happen before step 4, so the numbered file is what enters the manifest,
   and therefore before step 5, so a position enters the same root as the link record it counts:
   one seal, one snapshot, one bundle.
   This is also the only moment a merge of two checkouts has to pass through
   — two adds under different edges conflict on nothing, so git merges both silently and neither writer saw the other's run.
   The sort is deterministic and needs no human:
   a writer loses nothing, because a writer was never told a number.
4. `git add` the non-empty ones of the signer directories, `certs/`, `order/` and `seals/`
   — plus `imported/` and `receipts/` in a graph that has imported something, which section 10 covers.
   This list only ever *adds*;
   it does not bound the manifest.
5. Run the proof layer's seal (section 7) with the content anchor **off** — signatures only.
6. Write the snapshot `seals/<root12>/` (3.4) if it does not exist yet.
   This MUST happen **before** step 7:
   freezing runs per link and can fail part-way,
   and a certificate naming a root whose snapshot was never written can never be verified or exported again
   — a re-seal does not repair it,
   because the retry mints a different root.
7. For every link with no certificate,
   extract its inclusion proof and freeze it at `certs/<signer-cid>/<edge-cid>.cert.json`,
   and for every position with no proof, the same at `order/<signer-cid>/<edge-cid>.order.cert.json` (3.3).

**A repeated seal is not a no-op.** `seals/` is staged,
so each seal catalogues the snapshots of every seal before it
— the manifest differs, so the root differs, so another snapshot directory appears.
Measured over five consecutive seals with nothing added:
five distinct roots, manifest rows 3, 10, 13, 16, 19.
This is accepted with its cost, not designed;
a fixpoint would need a directory named after a root computed from a tree that already contains it.

What the manifest actually covers:
every git-tracked file under the graph home except `multiproofs/`, which the proof layer excludes as derived output.
Consequences worth stating:
a file this staging list never mentions is still sealed once the operator commits it,
and the registered pubkey is **not** under the seal
— it lives in `multiproofs/pubkeys/`,
and its authority comes from the signature it validates, not from inclusion.

**Time semantics.** The one provable time is the OTS anchor over the *signature*:
"the signer endorsed this no later than Bitcoin block N".
There is deliberately **no second anchor**.
Anchoring the root statement as well would date the record's bytes without saying who asserted them,
and a bundle carrying both would not say which one is the time
— so a reimplementation MUST anchor signatures only,
and MUST NOT report a content anchor as a permanently absent field.
The earliest provable bound is set by the first seal,
which is why certificates freeze.
Provable granularity equals seal frequency;
seal on every append.
A fresh stamp reads `pending` until Bitcoin confirms.

## 6. Bundle layout

A bundle is a plain directory.
It needs no git, no repo, no registered key and no network to check.

Birth bundle for an authored link:

```
<bundle>/
  <signer-cid>/<edge-cid>.json               # the record, at the leaf's filepath
  <edge-cid>.cert.json                       # exactly one *.cert.json at the root
  order/<signer-cid>/<edge-cid>.order.json   # the act's number, at ITS leaf's filepath (+ .order.cert.json beside it)
  seals/<root-hex-12>/                       # the seal the number was frozen under
  particles/<cid>[.ext]                      # the record's two ends, where held (default)
  multiproofs/tree-root.txt                  # + tree-root.txt.<fingerprint>.sig
  multiproofs/pubkeys/*.pub                  # named <fingerprint>.pub by the reference; the name carries no authority (2.4)
  multiproofs/ots-timestamps/tree-root.<HASH8>/…   # optional; absent ⇒ timestamp reports absent
```

There MUST be exactly one `*.cert.json` at the bundle root
— that is how a verifier finds the proof —
and the record MUST sit at the path the certificate's `leaf.filepath` names.
The seal artifacts (root statement, signatures, pubkeys, OTS bundles) live under `multiproofs/`,
because everything under that prefix is excluded from the manifest
and so cannot fold itself into the CID it is checking.
The certificate is the one proof file at the root,
which is where this layout departs from nu-multiproof's own portable shape (7);
it is safe here because every leaf this format proves is a file row, whose re-derivation reads no directory.

The OTS bundle belongs to the **birth** root, not to the current one.
`multiproofs/ots-timestamps/` holds one directory per seal,
each with a frozen copy of the root statement it stamped:
select the bundle whose frozen `tree-root.txt` carries the certificate's `root`.
Copying whatever `multiproofs/` holds at export time instead would ship a bundle claiming a time bound the certificate never earned.

The position and its proof travel at the paths the graph home files them under (3.5),
which is what lets one rule find them in a bundle and in a repo;
the proof is under `order/` and not at the root, so the "exactly one `*.cert.json` at the root" rule above still names the birth certificate alone.
Its seal goes to `seals/<root12>/` rather than into `multiproofs/`, always
— a backfilled position freezes under a later seal than its link,
so a bundle can carry two roots while `multiproofs/` holds one statement.
Where the two roots coincide that is a second copy of two small files,
and it is taken deliberately:
a verifier then looks the seal up by one rule instead of branching on whether they happen to agree.

Attaching the ends' particle files is the default:
without them a recipient has the *address* of the instruction a link states but not its preimage,
and can only decode the edge by scanning other repos.
Dropping them leaves the record and certificate alone.

## 7. Proof layer — normative by reference

The merkle and timestamp layer is [nu-multiproof](https://github.com/nushell-prophet/nu-multiproof),
and this spec does not restate it.
A reimplementation needs, from that project's `README.md`:

- **"Content manifest"** — `multiproofs/tree-hashes.csv`:
  one row per git-tracked file, per parent directory, and one `.` row;
  columns `filepath`, `content_sha256`, `content_git_sha1`, `content_git_sha256`, `content_cid`;
  rows under `multiproofs/` excluded.
- **"Tree specification"** — leaf ordering and charsets,
  leaf bytes (the five parsed field values joined with `\n`),
  RFC 6962 domain separation (`sha256(0x00 ++ leaf)`, `sha256(0x01 ++ left ++ right)`),
  the MTH split shape,
  proof-step encoding,
  and the root statement: exactly `multiproof-merkle-v4 <64 lowercase hex> <seq> <prev> <beacon>` plus one trailing `\n`,
  where `seq` is a decimal count with no leading zeros starting at 0,
  `prev` is the root that seal supersedes
  — or the literal `genesis`, which pairs with `seq 0` and with nothing else —
  and `beacon` is the seal's lower time bound:
  the literal `none`, or `bitcoin:<height>:<64 lowercase hex block hash>` naming a Bitcoin block nobody could have named earlier.
- **"Bundle contract"** — the OTS bundle grammar `<stem>.<HASH8>/`,
  including `<stem>.<ext>.<fingerprint>.ots`,
  the anchor over a signature that this format's time claim rests on.
- **"Verifying without the origin repo"** — the portable layout section 6 follows,
  except for the certificate's position (6).
  Its `--bundle` enumeration rule does not bite in this format, whose leaves are always file rows,
  but a reimplementation that ever proves a directory row needs it.
- **"Merkle inclusion proofs"** — the `content_verified` states, of which only `true` passes;
  a verifier SHOULD treat any non-boolean value as a divergence rather than enumerate them,
  so a state added upstream cannot drift out of sync.
  Its `manifest_root` cross-check applies to a repo, not to a bundle, which carries no manifest and reports `null`.
- **"Dating the endorsement"** — `absent`/`pending`/`anchored`,
  the Bitcoin height,
  the rule that the **earliest** anchor of the same bytes is the reported one,
  and that a stamp is matched to its signer by hashing the signature file rather than by its name.
- **the `seal` pipeline** (Quick start, "Sealing under an explicit key") — the order manifest → root statement → signature → stamp,
  the `<file>.<fingerprint>.sig` naming rule,
  and that the key must be registered before it can sign.

Four things this format fixes on top of it:
the content anchor is always off (5),
the per-seal snapshot directory `seals/<root12>/` (3.4),
the freeze rule for birth certificates (3.3),
and the single inclusion proof moved to the bundle root as `<edge-cid>.cert.json` (6).

## 8. Verification

One checker, and every entry point reduces to it:
a certificate, the content root its leaf resolves against, and the artifacts of the seal that certificate belongs to.
A bundle answers all three by itself
— one `*.cert.json` at its root, the leaf at its manifest path, the seal snapshot and pubkeys under `multiproofs/` —
and `verify-bundle <dir>` is that case.
Verifying in the repo names the same three instead:
`certs/<signer>/<edge>.cert.json`, the graph home, and `seals/<root12>/`.
The repo entry point takes the EDGE address — `verify <edge-cid> [--signer]` —
and runs this checker once per copy held:
each signer directory holding the edge against that signer's own certificate,
plus each imported bundle carrying it;
one row per copy.
It deliberately does not take the cyberlink CID:
the two kinds of CID can only be told apart by trying,
and a guessed argument fails silently
— a caller holding a link CID dereferences `particles/<link-cid>` first (3.2),
which resolves when some act named that cyberlink and published its preimage.
Same checker, same verdict,
so "verifies here" always means "verifies anywhere".

An implementation MUST NOT fold a birth certificate against the repository's *current* root statement.
The graph home's `multiproofs/tree-root.txt` moves with every seal;
a certificate is frozen at birth,
so the two agree only for links born in the newest seal.
The seal's own snapshot under `seals/<root12>/` is the artifact to check against (3.3).

Order matters — an implementation MUST NOT reach a later check with data an earlier one has not cleared.

1. **Locate the proof.** Exactly one `*.cert.json` at the root, else refuse.
2. **Canonical pubkeys.** Every `multiproofs/pubkeys/*.pub` MUST be canonical (2.4),
   compared as **bytes**, not as decoded text
   — decoding strips a UTF-8 BOM,
   and `EF BB BF` + a canonical line addresses to a different CID.
3. **Merkle verification.** Fold the proof to the root in the signed statement;
   check the SSH signatures over that statement;
   re-derive the leaf's content commitment.
   The content leg answers with a state, and only `true` passes
   — `missing`, `symlink`, `outside`, `directory` and `unverifiable` each block validity.
4. **Record self-addressing.** Read the record at `leaf.filepath` under both rules of 3.1,
   and require the CID v0 *form* of its signer directory — the parent half of the leaf path.
   Tampered bytes never reach the binding check.
5. **Signer binding.** The signer named by the leaf's path MUST be the CID of a pubkey that *validly signed the root statement*.
   Both sides of this match are key material.
   Matching a pubkey by filename is a hole:
   filing a victim's key as `<attacker-fingerprint>.pub`, with the attacker's own key beside it under any other name,
   binds the attacker's signature to the victim's signer CID
   and the bundle reads as the victim's authorship.
   This is also the check that gives the signer directory its authority:
   the path is inside the signed root (5),
   so a pair refiled under another signer's directory names a signer who never signed that root
   — or changes the leaf path and breaks the proof outright.
6. **Endorsement time.** Report the anchor over *that signer's* signature,
   matched through the same pubkey table.
   One signer may hold several signature files,
   so rank all of that signer's rows:
   an `anchored` row wins,
   and among those the **lowest** Bitcoin block, since the claim is "no later than T";
   failing that a `pending` row, which MUST NOT be ranked together with `absent`;
   failing that `absent`, meaning the endorsement is real but undated.
   A signer with no valid signature has no endorsement at all,
   which is a different answer from an undated one.

The verdict is a record, not a boolean.
`valid` is the conjunction of the merkle verdict and the signer binding.
A position (3.5) is folded by this same checker and reported as its own verdict beside it,
never inside `valid`
— and a bundle carrying none is an ordinary answer, not a failure.
That verdict is `false` when the position's proof folds but the position still states `added_at`:
the graph attests no times, so a signed claimed time is not a position in either state (3.5).
Malformed input (no certificate, a non-canonical pubkey) raises;
a cryptographic or content mismatch returns `valid: false` with the first failing reason.

## 9. Conformance vectors

Verified against the reference implementation on 2026-09-01 (`nu toolkit.nu test` — 216 passed).

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
| `{"op":"confirm_edge"}` | `QmcqM2jDzeLmPQYRVtMvJypmo8NS7xGh2HNgVLFepL5QKQ` |
| `{"op":"confirm_link"}` | `QmTJipuBLbsHCgRRe9BrGeGbZFFNoYFwzbiEQgGzDpaHNj` |
| `{"op":"deny_edge"}` | `QmXegbm1GjDayyetHt87fvAicrE42SQqfd7G4Gwnr1SSr5` |
| `{"op":"deny_link"}` | `QmZ27sgjKKC2HDS6o7Kk1L8PCANGxArGRxgNcay9ENC2jP` |
| `{"op":"agree_particle"}` | `QmUjmrKj4nYsbKg27ZSepjWFEyt54B5rMD6V4Mp4pUH3sA` |
| `{"op":"disagree_particle"}` | `QmQjBGThDKWcsBHZsCDtUL2GwB5FWoKXJM6Sfsgo3EtshK` |
| `{"cid_from":A,"cid_to":B}` (the edge address) | `QmawrHuBDdcSRCPumzsKfsMi5FJne8xai9WNPAdr3NmLBV` |
| `{"cid_from":A,"cid_to":B,"signer":S}` (the cyberlink) | `Qme4L2P7QwNoijw6HzYVrqrrtk99oj1XvJHvAb9yobHVLe` |

The first row is a link file's bytes — the pair;
its CID is the filename stem in the signer's directory.
The second row is the same act's triple
— written by no writer, and stored only when someone publishes it (3.2), whose CID is the cyberlink's derived address.
Reproduce any row with `printf '<bytes>\n' | ipfs add --only-hash --cid-version=0`.

**Signer identity.** The canonical form and the fingerprint are pinned by nu-multiproof (`nu-multiproof/pubkey.nu`'s `@example`, `tests/test_allowed-signers.nu`; the canonicalization itself in `tests/test_pubkey.nu`).
The signer CID is the row that couples 2.1 to 2.4 to 3.1 to the binding in 8.5:

```
line        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf
canonical   the same line plus "\n" — 81 bytes
fingerprint b610a91de8fa99e224f6b2e7fb6bb8c9e8f0303f8d72d14e5a494ab8d1c68011
signer CID  QmSxVNMd5zcxuoQ7TjgngUECWGSj4XCwK6oAQqwirUN9rx
```

**CID v0.** The table above exercises only the single-leaf path
— every record in it is far under one chunk,
so it cannot catch a mistake in the fold.
These five exercise the rest.
Let **P** be the 16 bytes `00 01 02 … 0f` repeated 16384 times,
which is exactly one 262144-byte chunk.

| content | CID v0 | what it pins |
|---|---|---|
| the empty file, 0 bytes | `QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH` | the omitted Data field, and that `filesize = 0` is emitted anyway |
| 262144 zero bytes | `QmRk1rduJvo5DfEYAaLobS2za9tDszk35hzaNSDCJ74DA7` | the chunk boundary — one leaf, not two |
| P ‖ P ‖ the first 1000 bytes of P | `QmWRgwTqCcE11Fs9rKviA8uxnACY5VWAyEJsCU44gD33ue` | one branch over three leaves: link order, Tsize, and blocksizes carrying filesizes |
| P repeated 175 times | `QmazZG2Fp65Los6G7GUjNgtSiJ9xxixYKNop6frmWR1QkK` | the 174-wide fold, and therefore a second level |
| the empty directory | `QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn` | a directory node with no links |

All five are recorded from the reference IPFS client (nu-multiproof `tests/test_cid-v0.nu`),
which also holds directory-tree and shard-boundary vectors.
An implementation that reproduces these and the first row of the record table has exercised every branch of 2.1
except a file DAG deeper than two levels (~7.9 GB), which nothing outside that repo pins.

## 10. Deliberately not specified

- **Custody, handoff and import.** Taking another signer's bundle, keeping it read-only, and re-exporting it with a signed chain of custody layers is a separate subsystem,
  described in `README.md` ("Bundles, import, provenance").
  Two of its consequences reach the path specified here.
  A birth bundle exported with a named recipient carries `<edge-cid>.handoff.json` and its signature **at the bundle root**,
  and the reference verifier folds that check into `valid`
  — so a bundle carrying one falls outside the verdict of section 8, which has no step for it.
  And a graph that has imported something stages `imported/` and `receipts/` into its seal as well,
  putting more rows in the manifest and so minting a different root;
  a graph that never imports has neither directory, so its manifest is unaffected.
- **Reading policy.** How to weigh repeats against confirms and denies, whose signature counts, how time decays
  — bj002 leaves this as `f(repeats, confirms, denies, signer_weights, time_decay)` and so does this format.
  A reader that sums them is making a policy choice, not implementing this spec.
- **Human names for keys.** Nothing here stores a label for a key anywhere.
  A `.pub` filename is decoration.
- **A provable lower time bound.** OTS bounds time from above only.
  "Created no earlier than" would need a recent unpredictable value inside the signed bytes.
- **Cross-signer aggregation.** A graph home is one signer's own record.
  A bundle received from another signer is that signer's copy, verified against its own birth seal;
  mixing the two would silently turn "what this signer said" into "what everyone said".
- **Retrieval.** CIDs name content, they do not publish it.
  Nothing here talks to an IPFS network.

## 11. Known limits

- Deriving content time through the signature inherits every way SSH verification can rot over decades,
  where a content anchor would stay a bare sha256 compare.
  That trade is taken knowingly (5).
- **Verification reads the OTS stamp, it does not confirm it.**
  The endorsement time of 8.6 is what the bundle's own attestation says,
  and that attestation is neither signed nor under the merkle root
  — it rides along beside them.
  So a bundle whose stamp names a Bitcoin height no block carries still verifies:
  the height is a claim by whoever assembled the bundle, not a proven bound,
  until a verifier checks it against Bitcoin itself
  (`ots verify` in the proof layer, which cross-checks independent block explorers and so needs a network).
  Everything else section 8 checks is offline and structural,
  which is why this one field is the exception worth naming.
- **A number is provable, a complete run is not shippable.**
  A stranger can be shown "this act is number 42, signed, dated no later than block N" (3.5).
  That 42 belongs to a run with no gaps is checkable only by someone holding the run:
  completeness is a property of the whole sequence, so a proof of it is the sequence.
  The limit is inherent, and it is why the bijection is enforced at the seal (5) rather than at verification.
- The reference implementation is a proof of concept, agent-written and never reviewed by an outside cryptographer.
