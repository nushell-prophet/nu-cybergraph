# Cybergraph format specification v1

This document gives what an independent implementation in any language needs.
The implementation needs it to write and read the same artifacts as `nu-cybergraph`.
These are:
the byte formats, the folder structure, the key format, and the procedures that produce and check them.

This document specifies only the mechanics.
The reasons are in `README.md`;
the concept is in `bostrom-journal` bj002 and bj003.
Where the two disagree with the code,
the code and its golden tests win,
and the difference is a bug in the prose.

**Pre-1.0.** There is no backward compatibility to keep.
Any change to section 2 or 3 recomputes every CID in every graph
and is a format version bump, not an edit.

This document uses MUST, MUST NOT, SHOULD and MAY as RFC 2119 defines them.

## 1. Terms

| term | meaning |
|---|---|
| particle | a file whose CID stands in an edge. The word names both the vertex of the graph and the bytes under that CID, the carrier of meaning (bj001: a file becomes a particle of the cybergraph when its CID stands in an edge). The store and the `particle` commands use the word particle for any published file, because a file is published to have a name |
| vertex | the same particle in the words of graph theory: its place in the graph, without its bytes |
| edge | the pair `{cid_from, cid_to}`: the unit of the operational layer. All signers that assert the edge share its one address |
| link, cyberlink | an edge that one signer asserts: the triple. Its file holds the pair, and the path holds the signer |
| signer | an identity: the CID v0 of an SSH public key file in canonical form |
| graph home | `<repo>/cybergraph/`: the whole graph of one signer |
| seal | one moment when the signer signs: manifest → merkle root → SSH signature → OTS stamp |
| birth certificate | the inclusion proof from the first seal that catalogued a link, frozen |
| bundle | a directory that holds all that is necessary to verify one link without the origin repo |

## 2. Primitives

### 2.1 CID v0

Every address in this format is a CID v0 of concrete bytes:
it is base58btc, and it is always `Qm` followed by 44 characters.

```
^Qm[1-9A-HJ-NP-Za-km-z]{44}$
```

It is IPFS UnixFS over DAG-PB,
and it is equal to the value that the reference client reports for `ipfs add --only-hash --quieter --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144`.
The text below gives the full construction,
so that an implementation needs no IPFS library.

**Constants.** The payload chunk size is 262144 bytes.
The number of links per intermediate node is 174 (go-unixfs `DefaultLinksPerBlock`: an 8 KiB block target divided by approximately 47 bytes per link).
The directory shard threshold is 262144.
The estimate for each entry is the length of its name plus 34.

**Varint** is unsigned LEB128:
while the value is 128 or more,
emit `(value mod 128) | 0x80`,
then divide the value by 128.
When the loop stops, emit the value that remains.
Negative values have no encoding,
and an implementation MUST refuse them, not encode them as two's complement.

**Protobuf framing.** A length-delimited field is `<tag byte><length varint><bytes>`.
Only these fields appear,
and the encoder emits them in the order of the table:

| message | field | tag | type |
|---|---|---|---|
| PBNode | Links | `0x12` | length-delimited, repeated: one per link, **before** Data |
| PBNode | Data | `0x0a` | length-delimited: the UnixFS message |
| PBLink | Hash | `0x0a` | length-delimited: the CID **bytes** of the child, `0x12 0x20` + the 32-byte digest |
| PBLink | Name | `0x12` | length-delimited: always emitted; `0x12 0x00` for a link to a file chunk |
| PBLink | Tsize | `0x18` | varint |
| UnixFS | Type | `0x08` | varint: 2 for a file, 1 for a directory |
| UnixFS | Data | `0x12` | length-delimited: the payload chunk |
| UnixFS | filesize | `0x18` | varint |
| UnixFS | blocksizes | `0x20` | varint, repeated: one per child, in link order; each is the **filesize** of the child |

In addition to its digest, a node has two numbers.
**Tsize** is the serialized length of its own block plus the Tsize of every node below it.
**filesize** is the payload bytes that it covers (only for file nodes).

**Leaf node** — one chunk of payload.
Its UnixFS message is Type = 2, then Data = the chunk, then filesize = the length of the chunk.
An **empty file omits the Data field entirely**
— it does not have a zero-length Data field —
but it still emits `filesize = 0`:
Data is the only conditional field,
and the protobuf practice to drop scalars with default values does not apply here.
The block is that message wrapped as PBNode.Data, with no links.

**Balanced fold.** Split the payload, in order, into chunks of 262144 bytes.
Make each chunk a leaf node.
An empty payload gives exactly one leaf over zero bytes.
Then, while more than one node remains, repeat the next two steps.
Cut the nodes, in order, into consecutive batches of 174.
Replace each batch with a branch node over it.

**Branch node.** The block is the links to its children, in order
— each `PBLink` has an empty Name —
followed by PBNode.Data.
That PBNode.Data holds UnixFS Type = 2 and filesize = the sum of the filesizes of the children.
It also holds one blocksizes entry per child, in link order.
Each blocksizes entry is the **filesize** of that child
— the payload bytes that it covers —
and not the size of its block.
The name of the field suggests that size.
A branch has no UnixFS Data field.

**Directory node.** The block is one PBLink per entry,
with the entry name as Name,
sorted **byte-wise by name**.
The link order is part of what the CID commits to.
PBNode.Data follows the links,
and it holds UnixFS Type = 1 and nothing else.
Take the sum over all entries of (byte length of the name + 34).
If that sum is more than 262144,
IPFS changes that directory to a HAMT shard.
This construction does not reproduce the CID of that shard.
In that case, refuse the directory;
do not emit a basic-directory CID that no IPFS client agrees with.

**The CID.** Calculate the sha2-256 of the serialized block.
Put the prefix `0x12 0x20` (multihash: sha2-256, 32 bytes) before it.
Encode the 34 bytes that result in base58btc with the alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.
Emit one leading `1` for each leading zero byte.
That prefix is constant,
and that is why every CID v0 shows as `Qm` plus 44 characters.

Only the manifest layer (7) needs directory CIDs.
Reference implementation: nu-multiproof `nu-multiproof/_cid-helpers.nu`;
the vectors are in 9.

### 2.2 Canonical record bytes

One serialization rule applies to every record that this format hashes
— both link records and derived records.

- The record MUST be flat,
  and every value MUST be a string.
  A reference to another record is the CID of that record, never a nested object.
- Keys are sorted by the byte order of their UTF-8 bytes:
  locale-free, case-sensitive.
- Compact JSON: no whitespace anywhere outside string values.
- Exactly one trailing `\n`.

A **derived CID** is the CID v0 of those bytes.
Reproduce any of them with `printf '<record>\n' | ipfs add --only-hash --cid-version=0`.

In practice, all values are CIDs and reserved `op` words.
Their character sets contain no character that JSON escapes,
so the bytes are reproducible without a policy for escapes.

### 2.3 Field types

| type | rule |
|---|---|
| CID | `^Qm[1-9A-HJ-NP-Za-km-z]{44}$` |
| timestamp | `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z\|[+-]\d{2}:\d{2})$`: RFC 3339, fractional seconds are optional |
| hash | `^[0-9a-f]{64}$`: sha256, lowercase hex |

Validation uses the exact key set:
an implementation MUST refuse a record with an unknown or missing key before it reads any value.

### 2.4 Signer identity — the key format

A signer is the **CID v0 of the bytes of its public key file**,
and those bytes have exactly one legal form:

```
<type> <base64>\n
```

No comment, no leading or trailing whitespace, no second line, no BOM.
The form excludes the key comment on purpose:
it is mutable metadata,
and if the form kept it, one key would split into several identities.

`<type>` MUST be one of:

```
ssh-rsa  ssh-ed25519
ecdsa-sha2-nistp256  ecdsa-sha2-nistp384  ecdsa-sha2-nistp521
sk-ssh-ed25519@openssh.com  sk-ecdsa-sha2-nistp256@openssh.com
```

The format refuses certificates (`*-cert-v01@openssh.com`).
It also refuses `ssh-dss`:
OpenSSH 10 removed DSA,
so it is not possible to verify such a key.

`<base64>` MUST be the encoding that OpenSSH itself writes for that key.
A check of the type prefix is not sufficient.
RFC 4251 permits a redundant leading zero byte in an RSA mpint.
OpenSSH removes that byte when it parses the key.
Thus a padded copy of a key loads correctly, shows the same fingerprint, and has a *different* CID.
The reference implementation solves this problem with a round trip:
it sends the line through `ssh-keygen -e -m RFC4716` and `ssh-keygen -i -m RFC4716`,
and it requires a fixed point.
An implementation MUST make an equivalent check;
if it accepts the bytes as they are, it gives one key a second identity.

Canonicalization is enforced at exactly two boundaries:
registration, and every read of the `multiproofs/pubkeys/` of a bundle at verification.
The second boundary includes a bundle made from the own key of this repo.
Thus each verification of an own link checks the registered key again.
A key is never checked again *in place*.
Thus a key that reached a trust list by any other route keeps the bytes that it has.
Its CID identity is different from the identity of the same key stored through registration.

There are two derived names.
Do not confuse them:

| name | value | used for |
|---|---|---|
| signer CID | CID v0 of the canonical bytes of the file | the signer directory that holds a link file; the `signer` field of the triple record; the signer binding at verification |
| fingerprint | sha256 of the base64-decoded key blob, lowercase hex | the pubkey filename; the middle segment of a `.sig` filename; the principal of nu-multiproof |

The **name of a pubkey file is decoration**.
Identity comes from the bytes inside it.
A verifier MUST NOT match a signer CID by filename
— hash the file contents, then compare.

A graph home has exactly one **authoring** identity,
but `multiproofs/pubkeys/` MAY hold several keys
— these are two different questions.
The directory is the trust list of nu-multiproof
— the keys whose signatures this format accepts.
Verification reads every valid signature over a root (8).
Thus a key registered beside the authoring key can add a signature,
but it can never take authorship.
The authoring identity is the key that the checkout itself signs with.
That key is `user.signingKey` in its git config.
`seal` signs the root with the same key.
The authoring identity is that key because the signer of a record MUST be a key that validly signed the root that catalogues it (8),
or the binding fails.
An implementation MUST resolve the authoring identity by key material:
the canonical form of the configured key equals the bytes of a registered file, never a filename match.
The reference implementation refuses to write when no key is configured at all, when the configured key is not registered, and when nothing is registered.
A single registered key is not an answer either.
This is because the trust list is exactly the place for a key that belongs to another person.
A command with a `--key` flag (export) resolves that key instead of the config.
Registration stays deliberate:
`init` establishes the identity,
and it MUST NOT grow a trust list that already holds one
— it undoes what such a run added.
A trust list states whose signatures a graph accepts,
so a key must never join it by accident.
A key joins beside the identity only by an explicit route,
`init --co-signer <key>.pub` in the reference implementation,
which registers and establishes nothing.
`seal` refuses only the zero case.

### 2.5 SSH signatures

Every signature in this format is a detached SSH signature (SSHSIG) over the exact bytes of a file.
The signer makes it and the verifier verifies it under the namespace **`file`**
— one fixed value, never the choice of a caller.
SSHSIG puts the namespace inside the signed preimage,
so this is not cosmetic:
a verifier that uses any other value rejects every good signature.
The value is fixed and not configurable,
because the code interpolates it into the rendered trust list.
There, a crafted namespace injects `cert-authority`
and makes every registered key trusted for anything.

Thus domain separation has to be in the signed bytes.
That is why the root statement is a single line that starts with the token `multiproof-merkle-v4` (7), and not a bare hash.

A signature is beside the file that it signs,
with the name `<file>.<fingerprint>.sig`.
Verification renders its trust list from the `multiproofs/pubkeys/` of the proof directory itself,
one line per key: `<fingerprint> namespaces="file" <type> <base64>`.

## 3. Repository layout

The graph home is always `<repo>/cybergraph/`.
`<repo>` is a directory inside a git repo, often its root.
The reference implementation takes `--repo`,
and by default it takes the nearest directory that holds `cybergraph/`,
from the current directory up to the git root.
A link names a particle.
But the bytes of that particle do not have to be there, or in the repo at all.
Links name CIDs, not paths.

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

The signer directories are at the graph root.
They are told from the reserved directories by their form only.
A directory with a CID v0 as its name is the directory of a signer,
and no reserved name matches that pattern.

**The tree above is closed.**
It is the full set of what can exist under the graph home.
An implementation MUST refuse anything else there, not ignore it
— this includes a hand-written `README.md` or `.gitignore` at `cybergraph/`.
The reason is that a seal signs all that is committed under the graph home.
And a signer must not be made to attest what they did not check.
Anything that is written by hand goes next to the graph home, not into it.
`multiproofs/` is the one directory that this section names but does not govern.
The directory belongs to the proof layer (section 7),
so an implementation recognises it and does not apply the closed-tree rule to its contents.
The rule also does not apply inside a bundle under `exports/` or `imported/`.
The reason is that a bundle is one artifact that is checked as a whole (section 8).
It does not apply inside a seal snapshot either, because the proof layer owns the snapshot.

Two refusals enforce the rule, and they answer different questions.
A reader MUST refuse a graph home if it does not recognise its **top level**,
and not report the graph as empty.
If a reader cannot tell a foreign layout from an empty one,
a silent misread goes into every count, tally and walkthrough that uses it.
A seal MUST refuse on the **whole** closed set (5), because the seal is the moment when those bytes get signed.
The reference implementation chooses the pubkey filename, and the filename carries no authority
— see 2.4.

A seal stages the signer directories, `certs/`, `order/` and `seals/` into git;
the seal does not stage `particles/` and `exports/` (see 5).
But if the graph reaches a store file, that file has to be in the index before the seal.
The seal refuses while the file is not in the index.

A sha256 git backend (`git init --object-format=sha256`) is recommended.
The format also works on sha1 repos.

### 3.1 Link record — `<signer-cid>/<edge-cid>.json`

The atomic edge, in the directory of its signer.
The file holds exactly the pair and nothing else, as two keys that are both CIDs:

```json
{"cid_from":"Qm…","cid_to":"Qm…"}
```

- The canonical rule (2.2) serializes the record.
  So the key order is alphabetical — `cid_from`, `cid_to` — the form is compact, and there is one trailing `\n`.
- The filename stem MUST be the CID v0 of the exact bytes of the file
  — this is the **edge address**, `derive {cid_from, cid_to}` under 2.2.
  When two signers state one edge, they share one filename, each in their own directory.
- The signer is **not in the bytes**:
  it is the directory name, which MUST be a CID v0.
  The seal binds the pair to the signer:
  the path goes into the signed root (5).
  If a file moves into the directory of another signer, its own proof breaks.
  A reader checks only the *form* of the directory;
  verification checks the binding (8).
- There is **no timestamp**.
  A time inside the record would split one act into a different CID for each moment of recording.
  Provable time comes from the seal (5);
  a claimed time is an ordinary edge (`claimed-at`, section 4).

The cyberlink — the triple `derive {cid_from, cid_to, signer}` — is computed, not stored:
the pair comes from the file, and the signer comes from the path.
The cyberlink is not the name of the file.

**Neither address is published by the writer.** A writer MUST NOT publish the pair or the triple as a store file when it writes the link.
The store holds bytes that a writer decided to put there,
never bytes that a command derived as a step of its work.
When a writer writes a link, the write points at the two endpoints of the link and at nothing else.
So `link add` publishes what its endpoints resolve to, and no more.

A derived address becomes dereferenceable when an act names it,
and the publication of the preimage is part of that act.
Section 4 puts the same rule on every record that a convention mints.
`confirm-edge A B` / `deny-edge A B` mint the pair as their target and publish it;
`confirm-link A B S` / `deny-link A B S` do the same for the triple;
to name either address in a plain link, publish it first (`particle add-edge` / `particle add-link`, 3.2).
Publication is idempotent,
so a second signer of the same edge writes nothing new,
and a convention that mints the same pair writes nothing new.

An implementation MUST NOT close this gap through a resolution of a derived CID from the link file that holds the same bytes.
The bytes are there, and the resolution would work.
But the resolution needs a second index next to the store,
and it puts a preimage where nothing pointed at one.

A reader MUST enforce both addressing rules,
from a **single** read of the bytes:

1. CID v0 of the raw bytes equals the filename stem.
2. Those raw bytes equal the canonical serialization of the parsed record.

Rule 2 is not redundant.
Keys in a different order, added whitespace, or a duplicate key each give bytes that hash to some other CID.
Those bytes would pass rule 1 under that name,
so one act would have two addresses.
Decode as UTF-8 explicitly;
if a reader guesses the encoding, a UTF-16 file can parse to the same pair under a different CID.

**Triple guard.** The path IS the triple
— the signer is in the directory, the edge is in the filename.
So a repeat of the same act lands on the same path.
A writer MUST return the existing record and not write a second file.
One act, one file.
The no-op still reads the file on disk again and checks it again first.
So a corrupted record fails loudly and does not read as a successful repeat.

### 3.2 Particle store — `particles/<cid>[.ext]`

Arbitrary content that is published as a self-addressed file, which stores the exact bytes:
no appended newline, no change of encoding.

- The address is always the bare 46-character CID.
  An extension is only a hint for presentation (a forge renders `.md`),
  and it matches `^[A-Za-z0-9]+(\.[A-Za-z0-9]+)*$`.
- One CID, one file.
  If existing content is added again under a different extension, nothing happens
  — the first name wins.
  A store that holds two files for one CID is broken
  and MUST fail fast on read, and never silently pick one.
- A reader MUST hash the bytes back to the CID before it serves them.
- For a reader, absence is ordinary:
  a link names CIDs, and the bytes do not have to be local.
  Absence and tampering MUST stay distinguishable.
  An optional read returns nothing for a CID that the store does not hold.
  An optional read still raises an error for a file that fails its hash.

The store holds content that a user published.
It also holds the instruction records and address records that conventions mint (section 4).
The store also holds the records that a writer publishes deliberately (`particle add-edge`, `particle add-link`) so that a later act can name them.
The publication of a derived record makes a derived CID readable
— the record is its own preimage.
The writer decides to publish the record:
the publication is never a side effect of the computation of an address (3.1).
A preimage MAY therefore sit in the store before anything names it
— the writer publishes it for a reference that they will make next.

The preimage of a canonical record MUST be publishable through the serializer of the implementation itself.
A preimage written by hand is not an alternative.
Any byte string other than the canonical form (2.2) hashes to a different CID.
Both files are self-addressed, so nothing reports the mistake.

The operands of that publisher are admitted by the same rule as the operands of every other write command.
A CID must resolve to bytes that this repo holds, unless the caller says otherwise.
Anything else is content, which the command publishes first and names by its CID.
One record MUST NOT have two admission rules.
A convention that mints a pair as its target and a caller who publishes that same pair directly make the same record.
What got in cannot depend on which command wrote the record.

A seal does not seal store files directly.
A file is time-anchored from the moment when a sealed link names its CID.
The reason is that bytes that hash to an anchored CID extend the anchor to those bytes when someone shows them.

But store files still have to be committed, and before the seal, not after.
The manifest is the git-tracked files (section 5),
so a store file outside the index goes into no root.
Then the anchor above reaches its bytes only for a person who already holds them.
A file is **reachable** when a link in this graph names its CID.
The link can name it as `cid_from`, `cid_to` or `signer`.
The link can name it as the pair record or triple record that is derived from a link, after someone published that preimage (3.1).
The CID can also be an operand inside a record that is reached in that way (section 4).
This rule applies again until nothing new appears.
If none of those reaches a store file, the file is published and linked to nothing.
Only its publisher can say if that was the intent.

### 3.3 Birth certificate — `certs/<signer-cid>/<edge-cid>.cert.json`

The inclusion proof that is extracted from the **first** seal that catalogued the link.
It is frozen forever.
The certificate is filed in the same layout as the link — the directory of the signer, the name of the edge.
JSON, 2-space indent (the bytes are not addressed, so the text format is free):

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

`path` is in leaf-to-root order, and `side` names the position of the **sibling**.
`root` is only a self-description
— a verifier folds to the root in the *signed statement*, never to this copy.

**Never regenerated.** Its OTS anchor is the earliest provable time bound of the link;
later seals only mint newer roots.
`verify` and `bundle` MUST use the birth seal, never the current root of the repo.

Whatever stands at a certificate path MUST be that certificate.
The bare existence of a file is not sufficient to decide "already certified".
A directory, an empty file, or a genuine proof whose `leaf.filepath` names a different link can stand at a certificate path.
Each of them leaves the link without a certificate while the link is catalogued.
So the certificate that a later seal writes names a later root than the birth of the link.
The reference implementation does this check at seal time only.
`verify` and `bundle` still branch on bare existence,
so junk at a certificate path reaches them as a crash and not as a verdict.

The same freeze rule governs a second proof, and the check above covers both proofs.
The position of a link (3.5) freezes at `order/<signer-cid>/<edge-cid>.order.cert.json`,
under the first seal that catalogues the number.
The position is never regenerated, for the same reason.
The root that the number went into makes the number provable,
and a later seal would move that root while the run reads the same.

### 3.4 Seal snapshot — `seals/<root-hex-12>/`

The directory name is the first 12 characters of the merkle root of the seal, in hex.
It holds the root statement of that seal and its signatures,
which are copied out of `multiproofs/` before the next seal overwrites them:

```
seals/<root12>/tree-root.txt
seals/<root12>/tree-root.txt.<fingerprint>.sig   # and/or the bare tree-root.txt.sig
```

This makes a frozen certificate exportable:
certificates verify against the root that they were born under,
and every seal overwrites `multiproofs/tree-root.txt`.

The snapshots are also the only place where a reader can read the run of seals.
A statement names its own `seq` and the root that it supersedes (7),
while `multiproofs/` keeps only the live one.
An implementation MUST read the snapshots in order, refuse a gap, and not report a shorter chain.
A run has no gap when `seq` runs from 0 to N and each `prev` is the root before it.
The reason is that a missing snapshot means that every certificate born under that root verifies against nothing.

### 3.5 Link position — `order/<signer-cid>/<edge-cid>.order.json`

The place of the act in the run of its signer, filed in the same layout as the link.
JSON, exactly one key, and the key *is* the state (the bytes are not addressed, so the text format is free):

```json
{"added_at": "2026-08-31T09:41:12+00:00"}
```

```json
{"seq": "42"}
```

`added_at` is the key while the position is provisional, and `seq` is the key after a seal has numbered it.
A position never has both keys, and never one key that holds the value of the other.
An implementation validates by the exact key set and refuses everything else.
So nothing has to infer the state from whether a proof is next to the file.

`added_at` is the `timestamp` type of 2.3, narrowed to UTC.
When the position is written and when it is read,
the zone offset MUST be `Z` or `+00:00`.
In both cases, a time in any other offset MUST be refused.
Nothing signs a claimed time, so a claimed time has value only if two files that state one instant state it in one way.
`seq` is a decimal count that starts at 0 and has no leading zeros.
This is the rule of the root statement for its own counter (7), not a second convention.
The file states **only** its one key, for this reason.
A certificate names the root that it folds to,
so a certificate cannot be inside the tree that produces that root.
But a position must be inside that tree.
So the proof that the position verifies against tells which seal minted the number, exactly as for a link record.

The number is not for indexing.
A run with no gaps makes the record of a signer provably complete,
so nobody can silently remove records from a replica.
This is the property that a counter per feed gives to an append-only log.
Everything below follows from that one purpose.

- **The run is per signer directory.** A graph home that holds several signer directories holds several runs, and each run starts at 0.
- **A writer writes the time, never a number**, on the same branch that writes the record.
  To give numbers needs a moment that sees the whole run at one time.
  A writer is not such a moment:
  the seal is (5).
  A repeat of the same act (the triple guard of 3.1) writes neither file.
- **The seal turns the time into a number** (5), and only the seal makes a `seq`.
  The provisional value is a time and not a counter because two runs have to be mergeable.
  If two checkouts each count 42, 43, 44, the only join puts one run fully before the other.
  That is not the order in which the acts occurred.
  But times interleave and recover the order that really occurred.
  The cost is clock skew between machines in place of counters that collide.
  This cost is the better failure of the two, because it makes the order worse but duplicates nothing.
- **Provisional until numbered.** The next seal MAY rewrite a position that states `added_at`;
  a position that states `seq` MUST NOT move.
  The record itself follows that rule — it is a file on disk until a seal signs it.
  That rule is what lets a user merge two checkouts at all (5).
  A claimed time goes into the graph home but never into a root.
  The seal replaces the claimed time before it stages the files, so no signature covers it, and the graph attests no times.
  A proof that folds to a root over a position that still states `added_at` is therefore not a position in any state.
  Such a proof MUST be refused.
- **A link that never reaches a seal keeps its time and never gets a number.**
  That is honest and not a gap.
  Nothing about an unsealed link is provable, and its record is not provable either.
- **The bijection is a seal-time refusal** (5): every link record has exactly one position, and every position names a link record.
  If one of the two halves is missing, the number does nothing that it exists for.
  A signer could seal a link and simply not give it a number.
  Then a reader that holds the full graph would see a contiguous run next to a link with no number.
- To verify a position, a reader folds the proof of the position, with the same machinery as for a record.
  The leaf path binds the number to the signer whose run it is.
  The verdict is reported **beside** the verdict of section 8, never folded into `valid`.
  The number states a fact about the run, not about whether the act is proven.
  A reader who weighs completeness has to see the two apart.
- A backfilled position is a position that is written for a link that is older than the run.
  A backfilled position freezes under a LATER root than the birth certificate of its link.
  A bundle carries that seal next to the birth seal (6),
  so such a bundle rests on two seals and not on one.

## 4. Conventions — instructions as ordinary edges

A convention encodes an instruction for the processing of the graph as a plain edge whose **source** is a derived CID.
The grammar has one atom and one constructor:

- An **address expression** is a leaf (an operand), or a record whose values are expressions too.
- An operand is an address when it matches the CID v0 pattern of 2.3.
  Otherwise the operand is content.
  A string that names an existing file publishes the bytes of that file,
  and any other string publishes itself.
  But a path-shaped string that names nothing MUST be refused and not published as its own text.
  So a caller cannot pass content that itself reads as a CID, or as a path, as content.
  Publish such content first, and pass the CID back.
- A nested record resolves to its derived CID,
  so the final record is always flat and 2.2 applies.
- The only exception is the value of an `op` key.
  That value is a reserved word of the format, used verbatim, and never treated as an operand.

Every record that passes through MUST be published as a file under `particles/`.
This lets a reader dereference an opaque source CID and get named fields back.

There are eighteen verbs for twelve conventions
— `confirm` and `deny` are one convention each and two verbs each, one verb per subject.
Four verbs match no bj002 convention:
`repeat` is edge repetition (bj002 names it next to the conventions, not among them — it puts no special CID in the source);
`claimed-at`, `update-particle` and `translation-particle` are extensions of this format, which the open set of bj002 permits.

If the verb has a subject, the `op` word names it
— `confirm_edge` / `confirm_link`, `deny_edge` / `deny_link`, `update_edge` / `update_particle`.
Where a verb has only one possible subject, the `op` word names it too: `agree_particle`, `disagree_particle`, `quote_particle`, `author_particle`, `translation_particle`, `answer_edge`.
The record shape does not name the subject:
`update_edge` and `update_particle` share `{about, op}`,
so only a reader that dereferences `about` sees the subject.
A CID is opaque.
No tool can tell a particle CID from an edge address at write time unless the preimage is already in the store.
So the word is the one check that always works.
If a writer puts a particle verb on an edge address, the word itself shows the mismatch.
Where a verb takes any CID on purpose, the word stays bare
— `pro`, `con`, `question`, `same`, `claimed_at`.
So a bare word is the signal "any CID".
Since 2026-09-02, bj002 spells the same words.
bj002 also derives from the same canonical record (2.2),
so an address here is the same address there.

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
| `pro X B` / `con X B` | `{"about":X,"op":"pro"}` / `{"about":X,"op":"con"} → B` |
| `question X Q` | `{"about":X,"op":"question"} → Q` |
| `answer-edge X Q R` | `{"about":{"cid_from":{"about":X,"op":"question"},"cid_to":Q},"op":"answer_edge"} → R` |
| `author-particle X P` | `{"about":X,"op":"author_particle"} → P` |
| `same P1 P2` | `{"about":P1,"op":"same"} → P2` |
| `update-edge A B C` | `{"about":{"cid_from":A,"cid_to":B},"op":"update_edge"} → C` |
| `update-particle B C` | `{"about":B,"op":"update_particle"} → C` |
| `claimed-at X T` | `{"about":X,"op":"claimed_at"} → T`, T is an RFC 3339 timestamp, published as a file |

A record in the source position or the target position means the CID of its canonical bytes.
Every source record has one of two shapes.
A verdict (`confirm`, `deny`, `agree`, `disagree`) has a fixed source `{op}` and has its subject in the target.
A relation has its subject in `about` and points at the other file.
When the subject is an edge, `about` holds the address of the edge.
The source of `answer-edge` nests two times.
First, the question record resolves to its CID.
Then the pair that names it and Q resolves to the edge address.
Then the outer record is serialized.

The edge address is `derive {cid_from: A, cid_to: B}` and the derived CID of the cyberlink is `derive {cid_from: A, cid_to: B, signer: S}`.
These are the two special cases of bj002, which are only records here.
The first is byte-identical to the link file itself (3.1),
but that does not make it a store file.
The link writer publishes neither address (3.1).
`confirm-edge A B` / `deny-edge A B` publish the pair because they mint it as their target.
`update-edge` / `answer-edge` publish the pair because they mint it as their subject.
So the edge address or cyberlink address that any of these verbs mints is always a published preimage.
The act that names the address publishes the address.

To read these edges back, a reader dereferences the source CID in `particles/`.
The CID of an operand appears as a literal string in every record that names it.
So a text search can narrow the set of candidate files.
But a search MUST only narrow.
The reader reads every file that remains, hashes it back to its name, and parses it exactly as it would without the search.
If a file only quotes a CID in prose, the search finds it and the read drops it.

Repeats, confirms and denies are separate signals,
and a format-level reader MUST NOT sum them.
A sum is a reading policy, and it belongs to the reader.

## 5. Seal procedure

A seal signs the whole graph home at one moment.
The proof layer has its root **at the graph home**, not at the git root.
Every manifest `filepath` is relative to `cybergraph/`,
and thus every leaf hash and every root is relative to it too.
This is why the `leaf.filepath` of a certificate reads `<signer-cid>/<edge-cid>.json` with no `cybergraph/` prefix.
The path goes into the signed root,
and this is also what binds each pair to its signer (3.1).
The normative order is:

1. Refuse if no pubkey is registered.
1a. Refuse if anything under the graph home is outside the closed tree of section 3.
   Step 4 stages those directories as a whole.
   So a file that the layout cannot describe would go into the signed manifest of this seal without validation.
   The signer would attest that file,
   but none of the checks that give meaning to an attestation would apply to it.
   To recover, remove the file or move it out.
   There is no override.
   A flag to sign past an object that the layout does not name is the thing that the closed set exists to prevent.
2. Read and validate **every** link record (3.1) in the signer directories
   — the directories at the root that have CID v0 names.
   Then check that what is at each certificate path is the frozen proof for that exact leaf.
   The same check applies to the proof path of each position (3.3).
   What is at a proof path has to *be* the proof for that exact leaf.
   Otherwise, step 7 would leave a signed proof beside bytes that the proof never covered.
   Refuse before the seal stages or changes anything.
   At a seal, a file on disk stops being junk and becomes a statement that this signer signed.
2a. Refuse unless every link record has exactly one position and every position names a link record (3.5).
   Also refuse unless the **numbered** run of each signer — the positions that state `seq` — is 0..N with no gap and no repeat.
   The first check is what makes a withheld link visible at all.
   This step cannot repair a failure of the second check.
   So this step reports the failure and does not fix it.
   A hole at 3 cannot be numbered away,
   because the numbers around it are already signed.
   So this seal would make the hole permanent and not name it.
   This is the refusal that 3.4 makes about a missing snapshot, for the same reason.
   Read the positions that state a `seq`, not the positions that a proof covers:
   `seq` is what "already assigned" means.
   A seal that stopped between step 3a and step 7 left numbers that no proof covers.
   If a seal gives out those numbers a second time, one number counts two acts.
3. Refuse if a store file that the graph *reaches* (3.2) is outside the git index.
   The manifest is the git-tracked files.
   So such a file goes into no root,
   while the link that names it is signed and frozen.
   The result is a certificate that proves an edge whose endpoint bytes nobody attested.
   An implementation MAY offer an explicit override to seal without those bytes.
   The override never reaches the layout rule of the store.
   Step 1a refuses a name under `particles/` that is not an address,
   and no override touches step 1a.
   Publication is the act of the signer,
   so this step refuses and does not stage the files for the signer.
3a. Number the **provisional** positions — the positions that state `added_at` (3.5).
   Sort them by that time.
   If two times are equal, sort them byte-wise by edge CID (the ordering rule of the manifest, so nothing new decides it).
   Assign consecutive numbers after the last number already assigned.
   Then rewrite each file to state `seq` in place of `added_at`.
   Compare the times as times, not as strings.
   Every claimed time is UTC (3.5),
   but `Z`, `+00:00` and fractional seconds still put one instant in several byte orders.
   Only a parse compares them correctly.
   This MUST happen before step 4, and thus before step 5.
   Step 4 then puts the numbered file into the manifest.
   Step 5 then puts a position into the same root as the link record that it counts:
   one seal, one snapshot, one bundle.
   This is also the only point that a merge of two checkouts has to go through.
   Two adds under different edges have no conflict,
   so git merges both silently,
   and neither writer saw the run of the other.
   The sort is deterministic and needs no human:
   a writer loses nothing,
   because nobody ever told a writer a number.
4. `git add` the non-empty ones of the signer directories, `certs/`, `order/` and `seals/`.
   In a graph that has imported something, the list also includes `imported/` and `receipts/`.
   Section 10 covers that case.
   This list only *adds*;
   it does not set a limit on the manifest.
5. Run the seal of the proof layer (section 7) with the content anchor **off** — signatures only.
6. Write the snapshot `seals/<root12>/` (3.4) if it does not exist yet.
   This MUST happen **before** step 7.
   The reason is that the freeze runs per link and can fail part-way.
   If a certificate names a root whose snapshot nobody wrote,
   nobody can verify or export that certificate again.
   A second seal does not repair it,
   because the retry makes a different root.
7. For every link that has no certificate,
   extract its inclusion proof and freeze it at `certs/<signer-cid>/<edge-cid>.cert.json`.
   For every position that has no proof, do the same at `order/<signer-cid>/<edge-cid>.order.cert.json` (3.3).

**A repeated seal is not a no-op.** `seals/` is staged,
so the manifest of each seal lists the snapshots of all the seals before it.
The manifest is different, so the root is different, so one more snapshot directory appears.
A measurement over five consecutive seals with nothing added gave this result:
five different roots, with 3, 10, 13, 16 and 19 manifest rows.
This behavior is accepted with its cost, not designed.
A fixpoint would need a directory with the name of a root computed from a tree that already contains that directory.

The manifest covers this:
every git-tracked file under the graph home except `multiproofs/`, which the proof layer excludes as derived output.
These consequences are important.
A file that the list of step 4 never names is still sealed after the signer commits it.
The registered pubkey is **not** under the seal.
The pubkey is in `multiproofs/pubkeys/`,
and its authority comes from the signature that it validates, not from inclusion.

**Time semantics.** The only provable time is the OTS anchor over the *signature*:
"the signer endorsed this no later than Bitcoin block N".
There is deliberately **no second anchor**.
An anchor over the root statement too would date the bytes of the record but not say who asserted them.
A bundle with both anchors would not say which one is the time.
For these two reasons, a reimplementation MUST anchor signatures only,
and MUST NOT report a content anchor as a permanently absent field.
The first seal sets the earliest provable bound,
and this is why certificates freeze.
The provable granularity is equal to the seal frequency;
seal at every append.
A new stamp reads `pending` until Bitcoin attests it.

## 6. Bundle layout

A bundle is a plain directory.
It needs no git, no repo, no registered key and no network to check.

The birth bundle for an authored link:

```
<bundle>/
  <signer-cid>/<edge-cid>.json               # the record, at the leaf's filepath
  <edge-cid>.cert.json                       # exactly one *.cert.json at the root
  order/<signer-cid>/<edge-cid>.order.json   # the act's number, at ITS leaf's filepath (+ .order.cert.json beside it)
  seals/<root-hex-12>/                       # the seal the number was frozen under
  particles/<cid>[.ext]                      # the record's two ends and every operand they reach, where held (default)
  multiproofs/tree-root.txt                  # + tree-root.txt.<fingerprint>.sig
  multiproofs/pubkeys/*.pub                  # named <fingerprint>.pub by the reference; the name carries no authority (2.4)
  multiproofs/ots-timestamps/tree-root.<HASH8>/…   # optional; absent ⇒ timestamp reports absent
```

There MUST be exactly one `*.cert.json` at the bundle root.
This is how a verifier finds the proof.
The record MUST be at the path that the `leaf.filepath` of the certificate names.
The seal artifacts (root statement, signatures, pubkeys, OTS bundles) are under `multiproofs/`.
The manifest excludes everything under that prefix,
so the seal artifacts cannot become part of the CID that they check.
The certificate is the one proof file at the root.
Here this layout is different from the portable shape of nu-multiproof (7).
This difference is safe here, because every leaf that this format proves is a file row.
The re-derivation of a file row reads no directory.

The OTS bundle belongs to the **birth** root, not to the current root.
`multiproofs/ots-timestamps/` holds one directory per seal.
Each directory has a frozen copy of the root statement that it stamped.
Select the bundle whose frozen `tree-root.txt` carries the `root` of the certificate.
A copy of what `multiproofs/` holds at export time would ship a bundle that claims a time bound that the certificate never earned.

The position and its proof go in the bundle at the paths where the graph home files them (3.5).
So one rule finds them in a bundle and in a repo.
The proof of the position is under `order/` and not at the root.
So the rule above of "exactly one `*.cert.json` at the root" still names only the birth certificate.
The seal of the position always goes to `seals/<root12>/`, not into `multiproofs/`.
The reason is that a backfilled position freezes under a later seal than its link.
So a bundle can carry two roots while `multiproofs/` holds one statement.
Where the two roots are the same, this is a second copy of two small files.
This cost is deliberate.
A verifier then finds the seal by one rule,
and does not branch on whether the two roots agree.

The particle files of the two ends are attached by default.
Without them, a recipient has the *address* of the instruction that a link states but not its preimage.
Then the recipient can decode the edge only with a scan of other repos.
Without the particle files, the record and the certificate stay the same.

## 7. Proof layer — normative by reference

The merkle and timestamp layer is [nu-multiproof](https://github.com/nushell-prophet/nu-multiproof),
and this spec does not state it again.
A reimplementation needs these parts of the `README.md` of that project:

- **"Content manifest"** — `multiproofs/tree-hashes.csv`.
  The file has one row per git-tracked file, one row per parent directory, and one `.` row.
  The columns are `filepath`, `content_sha256`, `content_git_sha1`, `content_git_sha256`, `content_cid`.
  Rows under `multiproofs/` are excluded.
- **"Tree specification"** — the leaf order and charsets,
  and the leaf bytes (the five parsed field values joined with `\n`).
  The section also covers RFC 6962 domain separation (`sha256(0x00 ++ leaf)`, `sha256(0x01 ++ left ++ right)`)
  and the MTH split shape.
  The section also covers the encoding of proof steps,
  and the root statement: exactly `multiproof-merkle-v4 <64 lowercase hex> <seq> <prev> <beacon>` plus one trailing `\n`.
  Here `seq` is a decimal count with no leading zeros that starts at 0.
  `prev` is the root that the seal supersedes
  — or the literal `genesis`, which goes with `seq 0` and with nothing else.
  `beacon` is the lower time bound of the seal:
  the literal `none`, or `bitcoin:<height>:<64 lowercase hex block hash>`, which names a Bitcoin block that nobody could name earlier.
- **"Bundle contract"** — the OTS bundle grammar `<stem>.<HASH8>/`,
  with `<stem>.<ext>.<fingerprint>.ots`,
  the anchor over a signature, on which the time claim of this format rests.
- **"Verifying without the origin repo"** — the portable layout that section 6 follows,
  except for the position of the certificate (6).
  Its `--bundle` enumeration rule has no effect in this format,
  because the leaves of this format are always file rows.
  But a reimplementation that proves a directory row needs that rule.
- **"Merkle inclusion proofs"** — the `content_verified` states, of which only `true` passes.
  A verifier SHOULD treat any non-boolean value as a divergence, and not enumerate the states.
  This way, a state added upstream cannot go out of sync.
  Its `manifest_root` cross-check applies to a repo, not to a bundle: a bundle carries no manifest and reports `null`.
- **"Dating the endorsement"** — `absent`/`pending`/`anchored` and the Bitcoin height.
  The section also covers the rule that the reported anchor is the **earliest** anchor of the same bytes.
  The section also covers the rule that a stamp is matched to its signer by the hash of the signature file, not by its name.
- **the `seal` pipeline** (Quick start, "Sealing under an explicit key") — the order manifest → root statement → signature → stamp.
  The section also covers the `<file>.<fingerprint>.sig` naming rule,
  and the rule that the key must be registered before it can sign.

This format sets four things on top of it.
The content anchor is always off (5).
Each seal has its own snapshot directory, `seals/<root12>/` (3.4).
Birth certificates follow the freeze rule (3.3).
The single inclusion proof moves to the bundle root as `<edge-cid>.cert.json` (6).

## 8. Verification

There is one checker, and every entry point reduces to it.
The checker takes a certificate, the content root that its leaf resolves against, and the artifacts of the seal that the certificate belongs to.
A bundle gives all three by itself:
one `*.cert.json` at its root, the leaf at its manifest path, the seal snapshot and pubkeys under `multiproofs/`.
`verify-bundle <dir>` is that case.
Verification in the repo names the same three items:
`certs/<signer>/<edge>.cert.json`, the graph home, and `seals/<root12>/`.
The repo entry point takes the EDGE address — `verify <edge-cid> [--signer]`.
The repo entry point runs this checker one time per copy held.
A copy is each signer directory that holds the edge, checked against the certificate of that signer.
A copy is also each imported bundle that carries the edge.
The result has one row per copy.
The repo entry point deliberately does not take the cyberlink CID.
The only way to tell the two kinds of CID apart is to try,
and an argument that is a guess fails silently.
A caller who holds a link CID dereferences `particles/<link-cid>` first (3.2).
This dereference resolves when some act named that cyberlink and published its preimage.
The checker is the same, so the verdict is the same,
and "verifies here" always means "verifies anywhere".

An implementation MUST NOT fold a birth certificate against the *current* root statement of the repository.
The `multiproofs/tree-root.txt` of the graph home changes at every seal.
A certificate is frozen at birth,
so the two agree only for links born in the newest seal.
The artifact to check against is the snapshot of the birth seal of the certificate, under `seals/<root12>/` (3.3).

The order is important — an implementation MUST NOT go to a later check with data that an earlier check has not cleared.

1. **Locate the proof.** If there is not exactly one `*.cert.json` at the root, refuse.
2. **Canonical pubkeys.** Every `multiproofs/pubkeys/*.pub` MUST be canonical (2.4),
   compared as **bytes**, not as decoded text.
   A decode removes a UTF-8 BOM,
   and `EF BB BF` + a canonical line has a different CID.
3. **Merkle verification.** Fold the proof to the root in the signed statement.
   Check the SSH signatures over that statement.
   Re-derive the content commitment of the leaf.
   The content check gives a state, and only `true` passes
   — each of `missing`, `symlink`, `outside`, `directory` and `unverifiable` blocks validity.
4. **Record self-addressing.** Read the record at `leaf.filepath` under both rules of 3.1.
   Require the CID v0 *form* for the signer directory of the record — the parent half of the leaf path.
   Tampered bytes never get to the binding check.
5. **Signer binding.** The signer that the path of the leaf names MUST be the CID of a pubkey that *validly signed the root statement*.
   Both sides of this match are key material.
   A pubkey match by filename is a hole.
   If a verifier matches by filename, an attacker can file the key of a victim as `<attacker-fingerprint>.pub`,
   with the attacker's own key beside it under any other name.
   This then binds the signature of the attacker to the signer CID of the victim,
   and the bundle reads as authorship by the victim.
   This check also gives the signer directory its authority.
   The path is inside the signed root (5).
   So a pair moved to the directory of a different signer names a signer who never signed that root.
   Or the move changes the leaf path and breaks the proof completely.
6. **Endorsement time.** Report the anchor over the signature of *that signer*,
   matched through the same pubkey table.
   One signer can hold several signature files,
   so rank all the rows of that signer.
   An `anchored` row wins.
   Among the anchored rows, the row with the **lowest** Bitcoin block wins, because the claim is "no later than T".
   If there is no anchored row, a `pending` row wins.
   A `pending` row MUST NOT be ranked together with `absent`.
   If there is no pending row, `absent` wins.
   An `absent` result means that the endorsement is real but has no date.
   A signer with no valid signature has no endorsement at all,
   and this is a different answer from an endorsement with no date.

The verdict is a record, not a boolean.
`valid` is the conjunction of the merkle verdict and the signer binding.
This same checker folds a position (3.5) and reports it as a separate verdict beside `valid`,
never inside `valid`.
A bundle that carries no position is a normal answer, not a failure.
That verdict is `false` when the proof of the position folds but the position still states `added_at`.
The graph attests no times,
so a signed claimed time is not a position in either state (3.5).
Malformed input (no certificate, a non-canonical pubkey) raises an error;
a cryptographic or content mismatch returns `valid: false` with the first reason for failure.

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

The first row is the bytes of a link file — the pair;
its CID is the filename stem in the directory of the signer.
The second row is the triple of the same act.
No writer writes the triple,
and it is stored only when someone publishes it (3.2).
Its CID is the derived address of the cyberlink.
Reproduce any row with `printf '<bytes>\n' | ipfs add --only-hash --cid-version=0`.

**Signer identity.** nu-multiproof pins the canonical form and the fingerprint (the `@example` of `nu-multiproof/pubkey.nu`, `tests/test_allowed-signers.nu`; the canonicalization itself in `tests/test_pubkey.nu`).
The signer CID is the row that connects 2.1 to 2.4 to 3.1 to the binding in 8.5:

```
line        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf
canonical   the same line plus "\n" — 81 bytes
fingerprint b610a91de8fa99e224f6b2e7fb6bb8c9e8f0303f8d72d14e5a494ab8d1c68011
signer CID  QmSxVNMd5zcxuoQ7TjgngUECWGSj4XCwK6oAQqwirUN9rx
```

**CID v0.** The table above tests only the single-leaf path.
Every record in that table is much smaller than one chunk,
so the table cannot find a mistake in the fold.
These five vectors test the rest.
Let **P** be the 16 bytes `00 01 02 … 0f` repeated 16384 times,
which is exactly one 262144-byte chunk.

| content | CID v0 | what it pins |
|---|---|---|
| the empty file, 0 bytes | `QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH` | the omitted Data field, and that `filesize = 0` is still emitted |
| 262144 zero bytes | `QmRk1rduJvo5DfEYAaLobS2za9tDszk35hzaNSDCJ74DA7` | the chunk boundary — one leaf, not two |
| P ‖ P ‖ the first 1000 bytes of P | `QmWRgwTqCcE11Fs9rKviA8uxnACY5VWAyEJsCU44gD33ue` | one branch over three leaves: link order, Tsize, and blocksizes that carry filesizes |
| P repeated 175 times | `QmazZG2Fp65Los6G7GUjNgtSiJ9xxixYKNop6frmWR1QkK` | the 174-wide fold, and thus a second level |
| the empty directory | `QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn` | a directory node with no links |

All five values are recorded from the reference IPFS client (nu-multiproof `tests/test_cid-v0.nu`),
and that file also holds vectors for directory trees and shard boundaries.
Take an implementation that reproduces these values and the first row of the record table.
That implementation has tested every branch of 2.1
except a file DAG deeper than two levels (~7.9 GB).
Nothing outside that repo pins that branch.

## 10. Deliberately not specified

- **Custody, handoff and import.** A separate subsystem takes the bundle of another signer and keeps it read-only.
  The subsystem also exports the bundle again with a signed chain of custody layers.
  `README.md` describes it ("Bundles, import, provenance").
  Two of its consequences reach the path that this document specifies.
  A birth bundle exported with a named recipient carries `<edge-cid>.handoff.json` and its signature **at the bundle root**.
  The reference verifier includes that check in `valid`.
  So a bundle that carries a handoff is outside the verdict of section 8,
  which has no step for it.
  Also, a graph that has imported something stages `imported/` and `receipts/` into its seal.
  So the manifest has more rows and the root is different.
  A graph that never imports has neither directory, so import does not affect its manifest.
- **Reading policy.** This policy covers how to weigh repeats against confirms and denies, whose signature counts, and how time decays.
  Like bj002, this format leaves the policy as `f(repeats, confirms, denies, signer_weights, time_decay)`.
  A reader that adds them makes a policy choice;
  it does not implement this spec.
- **Human names for keys.** Nothing here stores a label for a key anywhere.
  A `.pub` filename is only decoration.
- **A provable lower time bound.** OTS sets a time bound from above only.
  A claim "created no earlier than" would need a recent value that nobody can predict, inside the signed bytes.
- **Cross-signer aggregation.** A graph home is one signer's own record.
  A bundle from another signer is the copy of that signer, verified against its own birth seal.
  A mix of the two would silently change "what this signer said" into "what everyone said".
- **Retrieval.** CIDs name content;
  they do not publish it.
  Nothing here connects to an IPFS network.

## 11. Known limits

- The content time comes through the signature.
  So the content time gets every way that SSH verification can decay over decades,
  where a content anchor would stay a plain sha256 compare.
  This trade-off is a deliberate choice (5).
- **Verification reads the OTS stamp but does not check it against Bitcoin.**
  The endorsement time of 8.6 is what the attestation in the bundle says.
  That attestation is not signed and is not under the merkle root
  — it only goes beside them.
  So a bundle whose stamp names a Bitcoin height that no block has still verifies.
  The height is a claim by the party that assembled the bundle, not a proven bound,
  until a verifier checks it against Bitcoin itself.
  `ots verify` in the proof layer makes this check.
  That command cross-checks independent block explorers and thus needs a network.
  All other checks of section 8 are offline and structural,
  so this one field is the exception to name.
- **A number can be proved; a complete run cannot be shipped.**
  A bundle can show a stranger "this act is number 42, signed, dated no later than block N" (3.5).
  Only a person who holds the run can check that 42 belongs to a run with no gaps.
  Completeness is a property of the whole sequence,
  so a proof of completeness is the sequence.
  This limit is inherent,
  and it is the reason that the seal (5) enforces the bijection, and verification does not.
- The reference implementation is a proof of concept:
  agents wrote it, and no outside cryptographer reviewed it.
