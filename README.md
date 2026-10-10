# nu-cybergraph

A local cybergraph on a git backend:
content-addressed link records between particles.
Each link has an authorship proof and a birth-time proof, built on [nu-multiproof](https://github.com/nushell-prophet/nu-multiproof).

🚧 Proof of concept, agent-written, barely tested
— do not treat as secure.

## Origins

@mastercyb and @cyborgshead first invented and implemented the concept of Cybergraph in the Bostrom blockchain.
Cyberlink and Particle are their terms too.

## Concept

For any file, a CID (IPFS hash) can be computed.
The CID identifies the file uniquely,
and the file can be retrieved by its CID from the IPFS network.
A file becomes a **particle** of the cybergraph
when its CID is used in an edge of a cyberlink.
A particle is one name for two things:
a **vertex** of the graph and the bytes of the file under its CID.

A particle carries meaning:
the meaning occurs in the reader when the reader reads the content of the particle.
The store `particles/` and the `particle` commands hold any published file,
also a file that no link names yet:
a file is published so that a link can name it.

A **link** is a cyberlink:
a statement by a **signer**, "these two particles are connected".
Its pair `cid_from → cid_to` is an edge, directed from `cid_from` to `cid_to`.
A signer is an agent (for example, a human, an AI) that created and signed the cyberlink.
The identity of a signer is only the CID of the SSH public key of the signer,
so the signer can be referenced like any CID.
The cybergraph of a signer is a git repository of link records.

The design goal is cheap portability of each link:
one signer can give a single link to another party.
The link comes with a signature from its signer that the recipient can verify, and with a birth-time bound that the recipient can verify.
The signer does **not** sign each record separately, and does not send its whole graph.
The mechanism is a **birth certificate**:
sign one merkle root for each seal, and OTS-stamp that signature (the machinery of nu-multiproof).
Then freeze the inclusion proof of each link from the first seal that listed it.

## Quick start

```nushell no-run
use nu-cybergraph/

nu-cybergraph init                       # multiproof init + certs/ under <repo>/cybergraph/
nu-cybergraph init --co-signer k.pub     # …register a key beside the identity, so its signature over a root is read too
nu-cybergraph particle add "any text"    # publish content as particles/<cid>, get the CID
nu-cybergraph particle add-edge Qm…A Qm…B      # publish an edge address's preimage, so a later act can name it
nu-cybergraph particle add-link Qm…A Qm…B Qm…S # …the same for a cyberlink address (the triple)
nu-cybergraph particle cat Qm…           # read a stored file's exact bytes by its bare CID
nu-cybergraph particle uncommitted       # store files git does not have, and whether the graph names them
nu-cybergraph particle uncommitted --propose-commit # …and leave the git commit for the ones it names in the prompt, unrun
nu-cybergraph strays                     # anything under the graph home the layout does not describe
nu-cybergraph link add Qm…from Qm…to     # write <signer>/<edge>.json (non-CID args are published as particles first)
nu-cybergraph link list                  # the whole graph as a table, each edge with the verb it states
nu-cybergraph link touching Qm…          # which links name this CID, and in which position
nu-cybergraph link tally Qm…             # per verb and position: how many links, how many signers
nu-cybergraph link imported              # the same reading over every link a landed bundle carries
nu-cybergraph seal                       # sign the root + stamp that signature, freeze new certificates
nu-cybergraph seal --propose-commit      # …and leave the git commit for that seal in the prompt, unrun
nu-cybergraph seal chain                 # the run of seals, oldest first — refuses a gap
nu-cybergraph bundle Qm…edge             # portable bundle → exports/<signer>/<edge>/, particles the ends reach included (imported act: re-export + custody layer)
nu-cybergraph bundle Qm…edge --links-only # own act: …without particles, the record + certificate alone (no-op re-exporting an import)
nu-cybergraph bundle Qm…edge --to Qm…signer # …plus a signed handoff naming the recipient
nu-cybergraph import path/to/bundle      # verify, keep under imported/<signer>/<edge>/, write custody receipt
nu-cybergraph verify Qm…edge             # every copy held — own signers and imports — always against the birth seal
nu-cybergraph verify-bundle path/to/bundle # a bundle you received: check it with no repo of your own
```

## Link record format

The format is pinned exactly (reference: `nu-cybergraph/_record.nu`; golden bytes and CIDs: `tests/test_record.nu`),
so an independent implementation reproduces the same CIDs.

- The unit of the operational layer is the **edge**.
  The file holds exactly the pair
  — two string fields, `cid_from` and `cid_to`.
  The file is in the directory of its signer, `<signer-cid>/<edge-cid>.json`.
- Both fields are base58btc CID v0 (`Qm` + 44 characters).
  The **signer is not in the bytes**:
  the signer is the directory name
  — the CID of the SSH public key file of the signer.
  The seal binds the pair to the signer.
  The path goes into the signed root,
  so a file that moves into the directory of another signer breaks its own proof.
  Readers check only the CID v0 *form* of the directory.
  The record has no timestamp:
  time is in the seal and, as an option, in a `claimed-at` convention edge
  — see the time semantics below.
- **Canonical bytes**: keys in alphabetical order.
  The order is the byte order of the UTF-8 key bytes, with no locale.
  The JSON is compact (no whitespace),
  with exactly one `\n` at the end.
  This is the one canon of the format,
  and the same rule serializes derived records (see `convention derive` below).
  The charsets are constrained, so no JSON escape can occur,
  and the bytes are easy to reproduce.
- **Self-addressing**: the filename stem is the CID v0 of the exact bytes of the file
  — the **edge address**, `derive {cid_from, cid_to}`.
  So two signers that state one edge share one filename, each in their own directory.
  Readers reject a file when its raw bytes do not hash to its name.
  So a tampered file or a non-canonical file fails before a reader trusts any field.
- **The cyberlink has its own address.**
  The triple — `derive {cid_from, cid_to, signer}` — is computed from the pair in the file and the signer in the path.
  Both addresses are *derived*, and neither is published.
  This is because the store holds bytes that a writer decided to put there,
  not bytes that a command computed on the way.
  Also, the write of a link points only at its two endpoints.
  So `link add` reports `edge_cid` (the name of the file that it wrote) and **not** the derived CID of the cyberlink.
  This repo holds no file for that CID until someone publishes its preimage.
  `particle add-link A B S` publishes it,
  and `particle add-edge A B` does the same for the pair.
  The four confirm and deny verbs publish it themselves, because they mint it as their target.
  When the signer publishes the pair, the bytes are byte-identical to the link file.
  That duplication is accepted, not desired,
  and it is the price of one rule about the store.
  All of this is idempotent.
  So a second signer of the same edge writes nothing new, and a convention that mints the same pair writes nothing new.
- **Triple guard**: the path IS the triple
  — the signer in the directory, the edge in the filename.
  So the same act, written a second time, goes to the same path.
  Then `link add` returns the record that is already there, unchanged, and does not write a second file
  — one act, one file.
  This mirrors the consensus of Bostrom, which rejected a duplicate cyberlink.
  A later statement of the same act is a statement *about* the act (for example `convention claimed-at`),
  not a second copy of the act.
  The no-op still checks the self-addressing and the canonical form of the file on disk first.
  So a corrupted file at that path fails loud,
  and the command does not report it as a successful no-op.

Example
— the golden pair, the exact bytes of a link file (one line + `\n`, CID `QmUiARbMPT9WNXqvgb2BB9gWFXRiCEqD96AF5xebwNTCTT`):

```json
{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"}
```

Below is the triple record of the same act.
This record is not a file that `link add` writes.
It is the preimage that an act *about* this cyberlink publishes (CID `QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze` — the derived CID of the cyberlink):

```json
{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","signer":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}
```

Why JSON and not CSV/NUON:
every language and tool can read JSON (and nushell reads it natively).
CSV quoting is not canonical
(for the same reason, the merkle leaves of nu-multiproof hash parsed fields, not raw lines).
Certificates are JSON too, for the same reach
— nu-multiproof's `merkle prove`/`verify` use JSON natively.

## The particle store and text arguments

`particle add` publishes arbitrary content as a self-addressed file.
The command stores a string argument or piped content (string or raw bytes) as `particles/<cid>` with its exact bytes.
Then the command returns the CID.
It is idempotent: identical content is one file.
When a string argument names a path that exists, the command opens it and publishes its bytes.
For example, `particle add doc.md` publishes the file, not the six characters `doc.md`.
The reason: a caller who writes a path as a bare argument almost always means "publish this file".
When a path-shaped argument (a separator or an extension) names nothing, the command refuses it loudly.
It does not silently publish the argument as text,
because that is almost always a typo.
`--literal` is the escape hatch for the rare case when the caller means a path string as the content itself.
This does not change piped content in either case.
Piped content is always literal, path-shaped or not.
The pipe itself is the signal of deliberate intent.

`--ext` keeps a filename extension on the store file
— `particle add --ext md` writes `particles/<cid>.md`,
so a forge renders it as a document.
The extension is for presentation only, and it is never part of the address:
the CID is always the bare 46 characters.
Commands that read the store accept only that (`particle cat Qm…` — a filename or path is refused),
and they find the file whatever extension it has.
One CID, one file.
A second add of content that is already in the store, under a different extension, is a no-op (the first name wins).
A store that holds two files for one CID fails fast on read.
`particle cat` also verifies that the bytes hash back to the CID before it serves them.
So a tampered store file fails, and the command does not return it.

`particle cat --optional` returns null when this repo holds no file for the CID,
and it still raises an error on a tampered or ambiguous file.
A graph reader needs that split:
a cyberlink names CIDs, and the bytes do not need to be local,
so absence is ordinary.
But if a graph reader wraps the plain `cat` in `try`/`catch` to absorb the absence, the wrap also swallows the tamper error.
The tamper error is the one thing that the hash check exists to raise.

Every content argument of a write command (`link add`, `particle add-edge` / `add-link`, all convention verbs) accepts a CID v0 or content.
The command checks a CID against the store of this repo before it uses the CID.
Anything else resolves to bytes in the same way as the argument of `particle add`,
and the command uses its CID.
In that resolution, an existing path is opened,
a path-shaped argument that names nothing is refused,
and anything else is literal.
`--literal` forces literal.
So `convention question Qm… "who reviews this?"` publishes the question text and writes the edge in one call,
and `convention pro Qm… argument.md` publishes the file at that path as the argument.
There is one ambiguity — content that itself looks like a CID.
This ambiguity has a composable escape hatch, not a flag.
Publish the content explicitly with `particle add` (which never treats input as an address).
Then pass the CID that it returns.

By default, the command refuses a CID argument when this repo holds no file for it.
This is because nothing in content-addressing can tell a typo from a deliberate forward reference to bytes held elsewhere.
So refusal is the fail-fast default,
and `--allow-missing` is the escape hatch for the legitimate case.
This is a write-time check only.
The read side (`link list`/`touching`/`tally`, `particle cat --optional`) still treats local absence as ordinary.
This is because a cyberlink names CIDs, and the bytes do not need to be local.
A reader looks at a CID that someone else already stated.
A writer is the one who types the CID in.
That is why the two sides differ.

`--signer` publishes content too, because the signer can be referenced like any CID.
The command takes a CID v0 as the identity.
The command publishes any other string under `particles/` as its own bytes,
and the CID of those bytes becomes the signer.
Without the flag, the signer stays the identity of this repo.
This is what gives one repo several signers.
`init` registers exactly one key.
So ad-hoc named identities are the only way to try a multi-signer reading without new keypairs.
Examples of that reading are `tally`'s `signers` column and a `confirm-edge` from someone other than the author.
An endpoint has two rules that the signer deliberately does not have.
A signer string is **never** opened as a path:
`--signer other.pub` publishes those eight characters, not the key file.
This is because a signer names an identity, not a file.
A second reason is that a path branch would refuse an ad-hoc name that has a dot or a slash (`agent-1.v2`) as a probable typo.
To publish a key file, compose two commands instead
— `particle add other.pub`, then pass the CID.
And here a CID is **not** checked against `particles/` and needs no `--allow-missing`,
because a signer addresses a pubkey file.
That file is in `multiproofs/pubkeys/` and never in the particle store
— the identity of this repo would fail that check.
What the convenience does not do:
a signer minted from content has no key behind it.
So links that this signer states are local statements.
These links fail the signer binding at `verify`, `bundle` and `import`.

## Signer repo layout

```
cybergraph/
  <signer-cid>/<edge-cid>.json              # link records: pair in the file, signer in the path
  particles/<cid>[.ext]                     # the particle store, self-addressed: derived records and published content (extension optional, cosmetic)
  certs/<signer-cid>/<edge-cid>.cert.json   # birth certificates (frozen `merkle prove` output), mirroring the layout
  seals/<root-hex-12>/                      # archival root statement + signatures, one per seal
  exports/<signer-cid>/<edge-cid>/          # bundles built by `bundle` (default --out)
  imported/<signer-cid>/<edge-cid>/         # foreign bundles, verified on import, kept intact
  receipts/<author-cid>/<edge-cid>.receipt.json # custody receipts for imported links (+ frozen *.receipt.cert.json beside them)
  multiproofs/                              # nu-multiproof machinery (manifest, pubkeys, OTS)
```

Signer directories differ from the reserved names by form alone:
a root directory that has a CID v0 as its name belongs to a signer.

A sha256 git backend (`git init --object-format=sha256`) is recommended;
the merkle/certificate layer works on sha1 repos too.
Note that GitHub does not host sha256 repos
— Codeberg and plain remotes do.
This repo is on GitHub,
so its own history is sha1.

**Graph home.** The graph home is always `<git-root>/cybergraph/`
— `init` creates it, and every command finds it.
Particles are referenced by CID, not by path.
So their bytes never need to be under the graph home
— or in the repo at all.
The seal manifest covers only the graph subtree.
A file outside it still gets a time anchor at the moment when a sealed link mentions its CID.
The reason:
the anchor of a CID extends to any bytes that hash to that CID.
(Attestation of the files of a whole repo is a different job — for that, use nu-multiproof's `seal` directly.)

**The graph home is a closed set.** SPEC section 3 draws the whole tree that it may hold.
The tree holds the signer directories, `particles/`, `certs/`, `seals/`, `exports/`, `imported/`, `receipts/`, and `multiproofs/`, which belongs to the proof layer.
Nothing else may be there, and that includes a hand-written `README.md` or `.gitignore`.
The reason is the seal:
it stages those directories wholesale.
So if the layout cannot describe a file there,
the signer would sign that file without any of the checks that give a signature its meaning.
`nu-cybergraph strays` is the reading
— one row per path, the directory that holds it, and what that directory is allowed to hold.
`seal` refuses while that reading returns anything.
There is no flag to seal past it.
The rule stops where the authority of this repo stops.
The rule recognises `multiproofs/` but does not police it.
The rule also does not go inside a bundle under `exports/` or `imported/`.
`verify-bundle` checks such a bundle as one artifact.

Two refusals carry that rule,
and they answer different questions.
`seal` enforces the whole set,
because `seal` is the moment when those bytes get signed.
Every *reading* enforces the top level alone
— the level that says which layout this is.
It does so because a reader that cannot tell a foreign graph from an empty one answers `[]`, and the answer is believed.
That is not hypothetical.
On a graph that was still in the superseded `links/<link-cid>.json` shape, the readers reported 301 records as none at exit 0.
And `seal` succeeded:
it signed a root for links that it could not see, and it certified none of them.
A graph in that shape is not migrated.
That graph is older than the current format,
and the pre-1.0 rule is that old artifacts are refused, not converted.

## Conventions (bj002)

`bostrom-journal` bj002 has twelve conventions:
`confirm_edge`/`confirm_link`, `deny_edge`/`deny_link`, `update_edge`, `quote_particle`, `agree_particle`, `disagree_particle`, `pro`, `con`, `question`, `answer_edge`, `author_particle`, `same`.
These conventions *encode* an instruction to process the graph.
The conventions encode the instruction as an ordinary edge.
bj002 holds the concept and the reasons for it;
this section gives the mechanics.
`nu-cybergraph convention <verb>` writes the edge through the same record path as `link add` (triple guard, self-addressing, signer resolution),
so it takes the same `--signer`/`--repo` controls.
Four more verbs are not in the twelve.
`repeat` publishes the bare edge again.
bj002 names the repetition of an edge next to the conventions, but not as one of them.
The reason is that a repetition puts no special CID in the source
— no record exists that would go into the source.
`claimed-at`, `update-particle` and `translation-particle` are extensions of this repo:
`claimed-at` states a time as an edge.
Outside a seal, that edge is the only place where this format holds a time (see time semantics).
`update-particle` states the `update_edge` act of bj002 — "C replaces B" — about a particle instead of an edge.
A version chain of particles needs this act,
and the edge form of bj002 cannot express it.
`translation-particle` states that one particle says in another language what a different particle says.
A multilingual corpus is built on this relation.
Neither `same` (two names, one entity) nor `quote-particle` (checkable byte-for-byte) covers it.
The set of conventions in bj002 is open,
and that permits all three.
There are eighteen verbs and twelve conventions:
`confirm` and `deny` are one convention each and two verbs each.
The reason is that the split removes a name that hides its subject behind an optional argument.

The name of a verb and its convention word name the subject wherever the verb has a subject.
These verbs name their subject: `confirm-edge`/`confirm-link`, `deny-edge`/`deny-link`, `update-edge`/`update-particle`.
The verbs with only one possible subject also name it: `agree-particle`, `disagree-particle`, `quote-particle`, `author-particle`, `translation-particle`, `answer-edge`.
The shape of the record does not name the subject:
`update_edge` and `update_particle` share `{about, op}`,
so only a reader that dereferences `about` sees the subject.
Also, a CID is opaque.
At write time, no tool can tell a particle CID from an edge address
unless the preimage is already in the store.
So the word is the only check that always works.
A verb that names its subject is like a gender ending in grammar.
The verb repeats what the noun already says.
Exactly that repetition makes a mismatch visible without a parse of the sentence.
If a writer puts a particle verb on an edge address, the result does not read right.
Where a verb takes any CID on purpose, the word stays bare:
`pro`, `con`, `question`, `same`, `claimed-at`.
So a bare word is the signal "any CID".
Since 2026-09-02, bj002 uses the same words
and derives addresses from the same canonical record,
so an address here is the same address in bj002.

Every convention uses one primitive, the canonical record:
**`convention derive`** takes a flat record
and serializes it canonically.
The canonical form is compact JSON with keys in alphabetical order and exactly one trailing `\n`.
All values are strings:
no nesting, and a reference to another record is its CID.
**`convention derive`** then returns the CID v0 of those bytes, a **derived CID**.
To reproduce one, use `printf '<record>\n' | ipfs add --only-hash --cid-version=0`.
The record form is **the canon of bj002 itself**.
The appendix of bj002 defines a derived CID by these same bytes.
The one condition is that the encoding is the same for everyone.
The two special cases in the appendix are only records:
the edge address is `derive {cid_from: A, cid_to: B}`,
the derived CID of the cyberlink is `derive {cid_from: A, cid_to: B, signer: S}`.
`tests/test_convention.nu` pins this byte format, with the same discipline as the record format
— a change to it breaks every derived CID.
The link *file* above IS the pair record under the same rule,
so its self-address and the edge address are one CID.
In bj002 ("Cyberlink and cybergraph"), the pair addresses *what* is stated, and the triple addresses the act.
**`particle add-edge A B`** and **`particle add-link A B S`** are the half that stores.
These two commands serialize the same two special-case records canonically and store the bytes.
These two commands return the same CID that `derive` returns.
These two commands take components, not a record.
The reason is that a record built by hand with a wrong set of keys serializes without error.
That record gives an address that no derivation produces.
Nothing reports the wrong address, because the file is self-addressed in both cases.

An instruction is in the *source* of its edge
— a special CID such as `{"op":"deny_edge"}` —
so the source is opaque.
To make the source readable, every convention publishes each record that it mints
as a self-addressed file under `particles/`.
These records are the instruction and the address records that the instruction references.
Each record is its own preimage.
So when a reader dereferences the CID, the reader gets named fields with the real operand CIDs.
And a text search for the CID of an operand finds every record that the operand is part of (bj002 "Reading instructions").
Those files are not sealed directly.
A sealed convention edge names its source CID.
A sealed CID time-anchors any bytes that hash to it.
The same rule anchors any file that a sealed link names.

This table is the spec of the eighteen verbs.
A record in the source or target position means the CID of its canonical bytes.
The table has sixteen rows,
because `agree-particle`/`disagree-particle` and `pro`/`con` are mirror pairs, and each pair shares a row.
The header of `nu-cybergraph/convention.nu` gives the same table in the address-expression notation of the implementation
— the same facts in a second notation.
If a shape changes, both change together.

| verb | edge written |
|---|---|
| `repeat A B` | `A → B` (the plain edge published again — no instruction record, and not a convention) |
| `confirm-edge A B` | `{"op":"confirm_edge"} → {"cid_from":A,"cid_to":B}` |
| `confirm-link A B S` | `{"op":"confirm_link"} → {"cid_from":A,"cid_to":B,"signer":S}` (the cyberlink of a signer) |
| `deny-edge A B` | `{"op":"deny_edge"} → {"cid_from":A,"cid_to":B}` |
| `deny-link A B S` | `{"op":"deny_link"} → {"cid_from":A,"cid_to":B,"signer":S}` (the cyberlink of a signer) |
| `update-edge A B C` | `{"about":{"cid_from":A,"cid_to":B},"op":"update_edge"} → C` |
| `update-particle B C` | `{"about":B,"op":"update_particle"} → C` (extension, not in bj002; the same act about a particle instead of an edge — a version chain) |
| `quote-particle A B` | `{"about":A,"op":"quote_particle"} → B` |
| `translation-particle A B` | `{"about":A,"op":"translation_particle"} → B` (extension, not in bj002; B says in another language what A says, and the direction records which came first) |
| `agree-particle B` / `disagree-particle B` | `{"op":"agree_particle"\|"disagree_particle"} → B` |
| `pro X B` / `con X B` | `{"about":X,"op":"pro"\|"con"} → B` |
| `question X Q` | `{"about":X,"op":"question"} → Q` |
| `answer-edge X Q R` | `{"about":{"cid_from":{"about":X,"op":"question"},"cid_to":Q},"op":"answer_edge"} → R` |
| `author-particle X P` | `{"about":X,"op":"author_particle"} → P` |
| `same P1 P2` | `{"about":P1,"op":"same"} → P2` |
| `claimed-at X T` | `{"about":X,"op":"claimed_at"} → T` (extension, not in bj002; T is an RFC 3339 timestamp published as a file) |

The cyberlink target of `confirm-link` / `deny-link` is the triple record.
The verb publishes the triple record when it mints it.
So the preimage of the confirmed address is on disk,
and a reader who has the CID can open it.
The edge target of the two-argument forms is the pair record.
It is byte-identical to the link file itself,
and the act that names it publishes it in the same way.
`update-edge` and `answer-edge` publish that pair record too,
as their subject.

A source record has one of two shapes.
An evaluation (`confirm`, `deny`, `agree`, `disagree`) has a fixed source `{op}` and its subject in the target.
A relation has its subject in `about` and points to the other file.
When the subject is an edge, `about` holds the address of the edge.
This address is the same CID that an evaluation of that edge targets.
The address ties the act to that one edge,
so an update or an answer needs no copy of the fields of the edge.

## Reading the graph

A CID is opaque: `X → Y` says nothing about what X is.
bj002 tells how to read it back, in "Reading instructions"
— dereference the source.
This works because every convention publishes the record that it minted,
so the named fields of a derived CID are on disk.
Four commands do that:
three read this signer's own graph, and one reads what imported bundles carry.

| command | what it answers |
|---|---|
| `link list` | the whole graph, one row per record: `edge_cid` and `link_cid` (both are addresses), the pair as the store holds it, `signer` read from the path, then `op`, `src`, `tgt`, `src_tree`, `tgt_tree` — the verb that the source declares, the records of the endpoints as published, and the same records read back at every depth, where this repo holds them |
| `link touching <cid>` | which links name this CID, and **where**: `role` is `cid_from`, `cid_to`, `signer`, or a dotted path into the record of an instruction (`cid_from.about`, `cid_to.cid_from`) |
| `link tally <cid>` | one row per verb and position: how many links say it, and how many different signers signed them |
| `link imported` | the same rows as `link list`, but for every link that a landed bundle under `imported/` carries — one bundle at a time, and each bundle is decoded against its own `particles/`, never against those of this repo |

`role` is the part that a CID alone cannot carry.
As `cid_to` of an `update_particle`, a particle is the new version.
As `cid_from.about`, it is the replaced version.
As `cid_to.cid_from`, it is an endpoint of an edge that somebody confirmed.
As `signer`, it is the identity that signed the link.
The reader reads that identity from the path,
because the signer is the directory and not a field.
So no text search can narrow that case,
and every link in the directory of the signer names that identity.
A link that names the same CID in two positions appears twice
— that is a fact about the act, not a duplicate.

`touching` walks **upward** from the CID over the files that name it,
so the cost of a query is the neighbourhood, not the whole graph.
The CID of an operand is a literal string in every record that mentions the operand (bj002 again).
So, when `rg` is on PATH, `rg` first narrows the candidate files.
The gain is 0.5s instead of 41s over the graph of 567 links in the journal.
The search only narrows.
A file that does not contain the string cannot name the CID.
The reader reads every file that remains, hashes it back to its name, and parses it exactly as without the search.
If a file only *quotes* a CID in prose, the search finds it and the reading drops it
— the search never decides.
`--scan` skips `rg` and reads every record.
The rows are the same,
and `tests/test_read.nu` pins that equality,
so the fast path cannot become a second implementation.
If `rg` is not installed, the `--scan` path runs in any case.

Counts stay separate and are never summed.
Repetition and `confirm_edge` are different signals,
and work distinguishes them.
Repetition needs work:
only then does the signer state the same thing.
`confirm_edge` is support from a signer who did not do the work.
It relies on the one who did the work.
So a reader reports two numbers,
and the formula of bj002 keeps them apart as `f(repeats, confirms, denies, signer_weights, time_decay)`.
Where a signer cannot do the work personally,
only confirmation remains.
Several signers can propose an update from the one source `{"about":{"cid_from":A,"cid_to":B},"op":"update_edge"}`.
If a signer repeats the update of another signer, the signer claims that they independently invented the same replacement.
Thus the reader uses confirmations, not repetitions, to distinguish the versions that compete.
A sum is a read policy, and it belongs to the reader.

The aggregate is not the last step
— it is the next particle.
`link tally <cid> | to json | nu-cybergraph particle add` publishes the count as a self-addressed file,
and `link add` puts it in an edge with what it counts.
So the aggregate becomes an ordinary vertex that others can quote, confirm or deny without a new computation of it.

Two limits apply, and both are deliberate.
`list`, `touching` and `tally` read only own links (the signer directories at the graph root).
An imported bundle is the copy of another signer,
and `verify` checks the bundle against its birth seal.
If the readers mixed it in, they would silently turn "what this signer said" into "what everyone said",
and aggregation rests on that distinction.
So `signers` reads 1 in a fresh repo.
`link imported` is the way past that boundary,
and it keeps the distinction instead of removing it.
The rows arrive separately,
and each row carries the `signer` whose claim it is.
So a combination of the rows — consensus, cross-signer tallies, dedup — stays a read policy that the caller writes.
In the same way, `tally` never sums across positions.
Also, the reader hashes every file that it opens back to the CID that names it,
and that is the cost that remains:
`link list` reads the whole graph by definition and takes ~20 seconds over 567 links.
`touching` on a CID whose neighbourhood *is* the graph costs the same.
A signer is such a CID, because every link that the signer signed names it.

## Birth certificate

`seal` stages the signer directories and also `certs/ seals/ imported/ receipts/`.
Then it runs the `seal` of nu-multiproof (manifest → merkle root → SSH signature → OTS stamp).
Then it copies the root statement and the signatures of that seal to a snapshot under `seals/<root12>/`.
Only after that step does it look at each link that has no certificate yet.
For each such link, it extracts the inclusion proof of the link
and freezes it as `certs/<signer>/<edge>.cert.json`.
The snapshot is necessary because the next seal overwrites `multiproofs/tree-root.txt`,
but a certificate must verify against the root that it was born under.
The order is important, not an accident:
`seal` writes the snapshot *before* the certificates.
The freeze runs per link,
and it can fail before it is complete.
If a certificate names a root that has no snapshot,
nobody can verify or export that certificate again.
A new seal does not repair the certificate,
because the new attempt makes a different root.
Nothing makes a certificate again:
`verify` and `bundle` always use the birth seal, not the current root of the repo.

**A repeated seal is not a no-op.** `seals/` is one of the staged directories.
So each seal catalogues the snapshots of all the seals before it.
That is the custody continuity above:
each root attests again the earlier root statements and their signatures.
As a result, a seal always changes the manifest,
so it always makes a new root, also when nothing was added.
A measurement of five seals in sequence with no new link gave five different roots.
`seals/` grew from one directory to five,
and the manifest rows were 3, 10, 13, 16 and 19.
At the second seal the count jumps by seven.
Four rows enter at once: `certs/`, the certificate directory of the signer under it, the first certificate and the `seals/` parent row.
The first snapshot directory and its two files add three rows.
After that, each seal adds one snapshot directory and its two files.
If the OTS stamp is on, a run with no new content costs a new signature and a round trip to the calendar.
Keep this cost in mind against the advice to seal on every append.
A fixpoint needs a snapshot directory whose name is a root.
That root comes from a tree that already contains the directory.
That is a hash self-reference,
so in practice nobody can reach the fixpoint.

**Which seal is which.** A root tells what the tree held,
but never which seal it was.
So the root statement carries a counter: `multiproof-merkle-v3 <root> <seq> <prev>`.
`seq` starts at 0.
`prev` is the root that this seal replaced (the literal `genesis` for the first seal, and `genesis` pairs with `seq 0` and with nothing else).
`seal chain` reads every `seals/<root12>/tree-root.txt` in order.
It requires that `seq` runs 0..N with no gap,
and that each `prev` is the root before it.
If the chain has a break, `seal chain` raises an error and does not return a short table.
This is because a missing snapshot means that every certificate born under that root now verifies against nothing.
An absent `seals/` is the same break at full size,
so `seal chain` raises an error there too.
An empty table there would read as "no seals yet",
and a deleted directory looks exactly the same.
The counter is checkable *here*,
and not in a bare nu-multiproof repo, which keeps only the live statement.
This repo keeps every seal that it made,
because a birth certificate must stay verifiable against the seal that it was born under.
The limit of the counter: `multiproofs/` is outside the manifest,
so the merkle root does not cover `seq`.
`seq` rests on the signature over the statement and on the anchor of that signature.
What the counter gives: a removed seal is no longer invisible.

This repo accepts this behavior and its cost;
it is not a design choice.
If `seals/` is removed from the staged set, the seals do converge,
with a fixpoint at the second seal.
But the seals converge only while git does not track the graph.
When the graph is committed, the directory enters the manifest again through `git ls-files`.
This is because the staged set only *adds* files and never limits what the seal covers.
So this fix depends on a state that a shared graph must leave.
The unconditional fix is a gitignore entry for `seals/`.
Then nobody commits the snapshots, and every clone loses them.
Together with the snapshots, every clone loses the ability to verify or export any link born under those roots.

Precisely, the manifest covers this:
every git-tracked file under the graph home, except `multiproofs/`.
nu-multiproof excludes `multiproofs/` as derived output.
So the seal does *not* cover the registered pubkey
— git tracks it, but it has no manifest row.
Its authority comes from the signature that it validates, not from inclusion.

**The commit is the act of the signer; the wording is only proposed.** `seal` never commits.
The message, scope and time of a commit are decisions that `seal` has no context for.
`--propose-commit` does not change that.
The flag writes the commit into the prompt with `commandline edit` and stops,
so nothing runs until the signer reads it, edits it and presses enter.
The flag removes the other failure:
a seal that lands under "wip" or that is split over three commits.
That failure makes the log useless for the one question that the log is there to answer.
The question is this:
when was this root sealed, and what froze under it?
The subject is `seal: graph catalogued at merkle root <first 8 hex>`.
The root in it is truncated.
The reason is that all 64 hex characters push everything else off a `git log --oneline` line,
and the first 8 already identify the root.
The body states the root CID, the merkle root, the signer CID, and the count and kind of the certificates that froze.
It also states the `seals/<root12>` snapshot that they verify against, and the bundle with its endorsement anchor.
The content anchor never appears,
because `seal` always suppresses it.
The pathspec is what the seal owns end to end: the staged directories and also `multiproofs/`.
The pathspec adds them as whole directories, not file by file.
This is because a seal also *deletes* files there
— nu-multiproof clears a signature over bytes that the regeneration changed.
And no result field shows a deletion.
`particles/` is not in the pathspec on purpose.
To publish the bytes that a link names is an act of the signer,
and that act has its own commit (below).
`seal` does not stage `particles/` either.

**The store is committed before the seal, and `seal` refuses while it is not.** `link add` publishes its text endpoints as particles.
So the store grows when someone states an edge,
and not from a `particle add` that someone typed.
Also, the manifest is the git-tracked files,
so those files enter a root only if they were in the index first.
If the seal comes first, the link is signed and frozen,
but nothing catalogues its endpoint.
And nothing tells the signer about it.
The seal was successful.
Only a reader who came back later found a certificate
that proves an edge whose bytes nobody attested.
So `seal` refuses while the graph names a store file that git does not track.
`particle uncommitted` is the reading that the refusal uses.
That reading gives one row per store file that git does not hold clean.
Each row is marked `reachable`, `orphan` or `missing`.
`reachable` means that a link here names its CID, directly or as an operand inside a record that it names.
`orphan` means that the file is published, but nothing names it yet.
`missing` means that the file is tracked, but no longer in the working tree.
`--propose-commit` writes the `git add` and `git commit` for the reachable files into the prompt,
and does not run them,
exactly as `seal --propose-commit` does.
An orphan is never staged, and no flag includes it.
This is because a file that no link names is not in the graph.
So the commit of an orphan is a plain `git add`, not the business of this command.
The escape hatch is `seal --allow-untracked-particles`, which seals without those bytes.
The escape hatch never accepts a name under `particles/` that is not an address at all.
This is because the closed-set refusal below runs before the escape hatch,
and no flag changes that refusal.

**Time semantics.** The record carries no timestamp.
The reason is that a time inside the record would fork the same act into different CIDs, one per moment of the record.
Also, that time would still prove nothing.
The one time that can be proved is the OTS anchor of the birth seal over the *signature*.
The result reports it as `signer.endorsed`:
"the signer endorsed this no later than Bitcoin block N".
A link is a statement by a signer,
so that is the claim.
That claim is the one that must survive a key compromise.
The reason is that after a revocation at time R, only a signature datable before R still has a meaning.
An SSH signature has no time field of its own.
So without this anchor, a signature made today fitted a year-old bundle,
and nothing on disk contradicted it.
`verify` reports the endorsement of the signer of the record.
It matches the signer by key material, through the same pubkey table as the signer binding.
Each custody layer carries the endorsement of its custodian in the same way.
`absent` means that the endorsement is real but has no date;
it does not mean that the endorsement is missing.
There is deliberately **no second anchor**.
nu-multiproof can also stamp the root statement.
That stamp dates the bytes of the record
but does not say who stated them.
`seal` here always passes `--no-content-anchor` to suppress it.
With two anchors, nothing would say which one dates the statement
— both are true, and neither comes from the other on disk.
Each reader would then decide which one is the time, what a disagreement means, and if verification needs one or both.
One anchor leaves none of those questions open.
So this repo drops the `ots` field of upstream from the verify record,
and does not report it as always `absent`.
This repo accepts the price knowingly:
the content time comes through the signature,
so it gets every way that SSH verification can decay over decades.
A content anchor, in contrast, stays a bare sha256 compare.
The *first* seal sets the earliest provable bound,
and that is why certificates freeze
— later seals only add newer roots.
The provable granularity is equal to the seal frequency.
So seal on every append.
A seal costs one signature plus a free OTS stamp per signature for the whole batch.
A new stamp reports `pending` until Bitcoin confirms it (hours/days).
Any later seal in the origin repo upgrades it,
but a bundle that was exported before that seal keeps its pending stamp until somebody runs `ots upgrade` on it by hand.
A signer who wants to *claim* a time states it as an ordinary edge
— `convention claimed-at <cid> <rfc3339>`.
That claim is optional, per signer, and not proved.
A provable *lower* bound ("created no earlier than") would need a recent Bitcoin block hash inside the record.
Such a bound is out of v1 on purpose.

**Signer identity.** A signer is the CID v0 of the *file bytes* of its public key.
The spec pins one canonical encoding for those bytes: `<type> <base64>` and a trailing newline
— no comment, no extra whitespace.
Identity by bytes keeps verification easy to reproduce
(hash the file, then compare; the trust path does not parse the SSH format).
The canonical form keeps that hash stable,
and it moves the one parse that nobody can avoid to the boundary:
`init` canonicalizes the key at registration,
and `import`/`verify` reject a bundle whose pubkey file is not canonical.
The key comment is excluded on purpose.
The comment is mutable metadata (`user@host` changes across machines and new saves),
and it would silently fork one key into several identities.
Nothing replaces it: this toolchain stores no human label for a key anywhere.
If the signer renames a registered pubkey file, that is the affair of the signer,
and nothing reads the result.
`tests/test_roundtrip.nu` pins this with "a renamed pubkey file still exports a verifiable bundle".
One keypair is one signer
— distinct identities need distinct keypairs.
The identity of *this* graph is the key that the checkout signs with.
That key is `user.signingKey`, the same key that `seal` signs the root with,
or the `--key` that an export got.
That key matches a registered file by its canonical bytes, never by a filename.
So `multiproofs/pubkeys/` can hold more than one key without ambiguity.
Verification reads every valid signature over a root.
So a key registered next to the configured one can add a signature,
but that key never takes authorship.
`init --co-signer <key>.pub` is how a key joins.
A plain `init` refuses to grow a trust list that it did not start,
because a key must never be trusted by accident.

**Authorship.** A repo is the graph of one signer, sealed by the key of that signer.
The root signature covers every catalogued record,
so individual records carry no signature.
Authorship travels in the certificate:
a valid signature over the root statement, plus the merkle path, proves that the signer attested this exact record.
Verification also checks the **signer binding**.
By this binding, the signer that the path of the record names must be the CID of a pubkey that validly signed the root statement.
Without that check, anyone could seal the record of another person again under their own key.
The signature would then still verify
— against the wrong identity.
The binding also gives the signer directory its authority.
This is because the path enters the signed root.
So a pair filed again under another directory names a signer who never signed that root,
or its merkle proof breaks completely.
The binding says *who* signed;
`signer.endorsed` says *when they signed*
— the same lookup by key material, run against the endorsement anchors of the seal (see time semantics).

## Bundles, import, provenance

`bundle <edge-cid>` assembles the portable set of artifacts.
The set has the layout that nu-multiproof pins under "Verifying without the origin repo".
The set holds the record at its `<signer>/<edge>.json` path, the certificate and the signer pubkeys.
The set also holds the root statement + signatures of the birth seal, and the OTS bundles that commit to that root.
By default, the set also holds a copy under `particles/` of each end of the record that this repo holds a file for.
By default, it also holds a copy of every operand that an instruction preimage among those ends names, at any depth.
When more than one signer holds the edge, `--signer` names whose act leaves.
Without it, `bundle` refuses several candidates and never guesses.
Without those bytes, an importer has the special CID of the instruction that a link states (e.g. `{"op":"agree_particle"}`), but not its preimage.
The importer can then decode the meaning of the edge only by a scan of `particles/` across every repo that it can reach.
`--links-only` reduces the birth bundle to the record + certificate alone.
(`--links-only` is a no-op for the re-export of an imported link.
That bundle is copied unchanged, particles included, per the read-only-foreign-authority rule below.)
Anyone can verify it offline, with no access to the origin repo:
`verify-bundle <dir>` is that command,
and it needs nothing else — no repo, no registered key, no network.
`verify-bundle` returns the same record that `verify` returns for a local link,
because it is the same check.
`verify <edge-cid>` runs the same checker over the repo itself, once per copy that the repo holds.
`verify` points the checker at `certs/<signer>/<edge>.cert.json` and the snapshot of the birth seal under `seals/`;
`--signer` narrows the check to one act.
`import` also verifies, but it is the stronger act.
`import` needs an initialized repo with a registered pubkey,
and it writes a custody receipt.
So `import` is the command to *take* a bundle, not to *check* one.

`import <bundle>` verifies first (merkle structure, signature, record self-addressing, canonical pubkey form, signer binding, and every custody layer — below)
and refuses invalid bundles loudly.
A valid bundle goes intact into `imported/<signer-cid>/<edge-cid>/`.
The bundle stays the authority of the link for authorship and birth time forever.
The copy is read-only: a re-export passes it along unchanged.
Import also writes a **custody receipt** at `receipts/<author-cid>/<edge-cid>.receipt.json`, outside the read-only copy and in the same layout as the links.
The author directory and the edge name together address the act as unambiguously as the derived CID of the cyberlink.
If the edge alone were the key, it would collide as soon as the copy of the same edge from a second author arrives.
The receipt is `{cid_from, cid_to, signer, custodian, received_at, files, prev, handoff}`.
The first three fields spell out the cyberlink and do not address it.
So `convention derive` over them recovers the derived CID of the cyberlink,
while the receipt itself needs nothing external to say what it is about.
A receipt is not content-addressed,
so a lone derived CID here would name an act whose preimage is somewhere else.
When the receipt spells out the components, it removes that dependency and does not need to satisfy it.
A stranger who holds one custody layer reads the act from the bytes of the receipt.
That stranger has no store to consult and no CID to trust.
`import` publishes no preimage for the cyberlink that it lands.
To take custody of an act is not to speak about it.
So the store of the custodian gets that file only when the custodian decides to speak about the cyberlink (`particle add-link`).
`files` is a path+sha256 manifest of the birth-bundle files as received.
`prev` is the sha256 of the receipt file of the previous custody layer (null for the first custodian).
`handoff` is the sha256 of the handoff that the bundle arrived by (null when it arrived without one).
The next `seal` catalogues the receipt and freezes its inclusion proof next to it as `receipts/<author>/<edge>.receipt.cert.json`.
This is the same freeze rule as for birth certificates:
the first seal sets the earliest provable custody bound.

`bundle` on an imported link **re-exports** it:
it copies the foreign bundle unchanged,
and appends the custody layer of this repo under `custody/<n>-<signer12>/`.
A layer is a proof bundle in the birth layout.
The layer holds the receipt at its `receipts/` path and its frozen proof at the layer root.
The layer also holds the root statement + signatures + pubkeys + OTS of its seal.
So the same machinery verifies the layer.
That machinery checks the structure, the signature and the custodian binding.
For the custodian binding, the `custodian` of the receipt must be the CID of a pubkey that signed validly.
That machinery also checks `files` against the actual birth bytes, and the `prev` chain with contiguous layer numbers.
The chain makes a dissemination path provable *in order*.
The receipt of layer *i* commits to the receipt of layer *i−1*.
So a stranger who holds only the bundle can check this:
"A authored it, then B held it no later than block K_B, then C no later than K_C".
Provenance grows in layers, and the original certificate does not change.
Each receipt stays constant-size (a new list of the prior layers in each receipt would grow the chain quadratically).

**Handoff.** Custody proves that a holder *held* the bundle;
without more, the direction ("B → C") is only an inference from who held what.
`bundle --to <signer-cid>` makes it a signed claim.
The claim is a handoff file `<edge-cid>.handoff.json` — `{schema, cid_from, cid_to, signer, from, to, receipt, handed_at}` — and a detached SSH signature.
`bundle` writes both at the bundle root (author) or inside the custody layer of the sender (custodian).
The file states the act and does not address it, exactly as a receipt does.
`cid_from`/`cid_to`/`signer` are the three components of the cyberlink.
So the file says which act it moves without a store to dereference a CID in.
And `convention derive` over them recovers the address anyway.
`signer` is the author of the act and does not move;
`from` and `to` are the two holders of this transfer,
and they are the same as `signer` only for the handoff of the author.
The handoff file is the one artifact that is signed directly and not through a seal.
This is because the bundle leaves at export time, before a later seal can catalogue it.
`schema` is the constant `"cybergraph-handoff-v2"` and comes first.
So the signed bytes start with a tag that names what they are.
This is because every SSH signature that this toolchain makes is under the single `file` namespace.
So a signature over untagged bytes could be replayed into any other context where the key signs bytes.
Verification requires the token byte-exact
— the JSON counterpart of the one-line root statement of nu-multiproof.
`receipt` pins the sha256 of the receipt of the sender (null for the author).
So `receipt` ties the claim to the exact chain state that was handed over.
The receipt of the recipient hashes the handoff back (its `handoff` field).
So after the recipient seals, nobody can strip the claim of the sender from the chain.
Verification binds the signature to the identity of the sender.
That identity is a pubkey that signed validly and whose CID is `from`
— the handoff twin of the signer binding.
Verification also checks the seam:
the handoff of the previous holder must name the custodian of the next layer.
`import` refuses a bundle handed to someone else
— its own custody layer could never verify.
The refusal is a fail-fast for honest importers, not a boundary against an interceptor (see the limits below).
A handoff is optional (an open export names no recipient).
A handoff is a claim that the sender *sent* the bundle, not a proof of delivery.

Three honest limits.
The custody bounds are upper bounds.
The chain proves that each receipt existed before the seal of the next custodian.
The chain does not prove when a hop actually happened.
A receipt pins the birth files byte for byte.
So a change to an imported copy breaks the `files` commitment of every receipt taken over those bytes.
`ots upgrade` inside the copy is such a change.
Upgrade stamps in the `multiproofs/` of the repo of the custodian itself, never inside `imported/`.
And until the recipient seals, a handoff is only a file in the bundle.
Whoever holds the bytes can strip it (with its signature) and import the bundle as an open one.
That erases the directional claim of the sender.
The seal makes a handoff permanent, not the misaddressed-import refusal.

## Dependencies

- [nu-multiproof](https://github.com/nushell-prophet/nu-multiproof), which this repo carries at `nu-multiproof/`
  — the `nu-cybergraph/_deps/` shims are the one place that resolves it.
  A clone holds the exact version that this repo was tested with;
  nu-multiproof is also published on its own, from the same directory.
- `rg` ([ripgrep](https://github.com/BurntSushi/ripgrep)), optional and only for `link touching`/`link tally`:
  it narrows which files the reader opens.
  If `rg` is absent, the same commands read every record and return the same rows.
  Correctness does not depend on `rg`,
  and that is why `rg` can be optional at all.
- `git` and `ssh-keygen`, nothing else:
  this repo computes per-file, per-directory and root CIDs in pure nushell,
  so no `ipfs` CLI is necessary.

## Testing

The tests require [nutest](https://github.com/vyadh/nutest) as a live sibling checkout at `../nutest`,
the path that `toolkit.nu` imports.
The suite of nu-multiproof runs from `nu-multiproof/` and imports `../nutest` too,
so it also needs nutest inside the clone, at `nutest` (gitignored).

```nushell no-run
use toolkit.nu *; main test
```

Tests run fully offline: the OTS stamp is the only network call that the seal path makes,
and there are two ways past it.
Most tests pass `--no-stamp` and skip the stamp completely;
a few pass `--response-file` instead.
That flag takes the answer of the calendar from a local fixture,
and so gets a real stamp with no network.
In those tests, a status reads `pending`, not `absent`.
The two flags are alternatives, and `seal` refuses them together,
because with `--no-stamp`, nobody would read the fixture.
A calendar can only answer `pending`,
because confirmation happens later, in a block.
So the suite reaches `anchored` when it builds a Bitcoin attestation offline.
That is the one OTS byte format that this suite writes for itself.
CIDs need no external call at all, and the suite of nu-multiproof tests the rest of the OTS internals.
