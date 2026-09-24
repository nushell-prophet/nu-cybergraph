# nu-cybergraph

A local cybergraph on a git backend:
content-addressed link records between particles, with per-link authorship and birth-time proofs built on [nu-multiproof](https://github.com/nushell-prophet/nu-multiproof).

🚧 Proof of concept, agent-written, barely tested
— do not treat as secure.

## Origins

The concept of Cybergraph was first invented and implemented by @mastercyb and @cyborgshead in the Bostrom blockchain.
Cyberlink, Particle and Neuron are their terms too.
Initially I resisted using them,
but after tons of iterations I came to the conclusion that they deserve their own names,
due to the uniqueness and substantiality of Cybergraph.

Three of the four stay coined here
— *cybergraph*, *cyberlink*, *particle*.
A **particle** is a carrier of meaning:
the meaning arises in the reader when they read its content (`bostrom-journal` bj002, "Cyberlink and cybergraph").
Its content is the bytes of a file;
its name is the CID v0 of those bytes;
its role is a **vertex** of the graph,
which it becomes when its CID stands in an edge.

*Neuron* is the one term this repo drops:
the one who signs a cyberlink is a **signer**, which says what it does here and needs no gloss.
`neuron` is kept only where the text quotes Bostrom.

## Concept

Everything published here is a **particle**:
bytes addressed by the CID v0 of those bytes,
a carrier of meaning that becomes a **vertex** of the graph the moment its CID stands in an edge.
A **link** is a directed edge between two particles, asserted by a **signer**
— an identity that is itself just the CID of an SSH public key,
so a signer is referenced like any other particle.
A signer's cybergraph is a git repository of link records.

The design goal is cheap per-link portability:
one signer can hand a single link to another with a verifiable signature from the link's signer and a verifiable birth-time bound,
**without** signing every record individually and without shipping its whole graph.
The mechanism is a **birth certificate**:
sign one merkle root per seal and OTS-stamp that signature (nu-multiproof's machinery),
then freeze each link's inclusion proof from the first seal that catalogued it.

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
nu-cybergraph bundle Qm…edge             # portable bundle → exports/<signer>/<edge>/, ends' particles included (imported act: re-export + custody layer)
nu-cybergraph bundle Qm…edge --links-only # own act: …without particles, the record + certificate alone (no-op re-exporting an import)
nu-cybergraph bundle Qm…edge --to Qm…signer # …plus a signed handoff naming the recipient
nu-cybergraph import path/to/bundle      # verify, keep under imported/<signer>/<edge>/, write custody receipt
nu-cybergraph verify Qm…edge             # every copy held — own signers and imports — always against the birth seal
nu-cybergraph verify-bundle path/to/bundle # a bundle you received: check it with no repo of your own
```

## Link record format

Pinned exactly (reference: `nu-cybergraph/_record.nu`; golden bytes and CIDs: `tests/test_record.nu`),
so an independent implementation reproduces the same CIDs.

- The unit of the operational layer is the **edge**:
  the file holds exactly the pair
  — two string fields, `cid_from` and `cid_to` —
  and lives in its signer's directory, `<signer-cid>/<edge-cid>.json`.
- Both fields are base58btc CID v0 (`Qm` + 44 chars).
  The **signer is not in the bytes**:
  it is the directory name
  — the CID of the signer's SSH public key file.
  What binds the pair to the signer is the seal:
  the path enters the signed root,
  so a file moved into another signer's directory breaks its own proof;
  readers check the directory only for CID v0 *form*.
  There is no timestamp in the record:
  time lives in the seal and, optionally, in a `claimed-at` convention edge
  — see time semantics below.
- **Canonical bytes**: keys in alphabetical order
  — byte order of the UTF-8 key bytes, locale-free —
  compact JSON (no whitespace), exactly one trailing `\n`.
  This is the one canon of the format,
  the same rule that serializes derived records (see `convention derive` below).
  The constrained charsets mean no JSON escaping can occur,
  so the bytes are trivially reproducible.
- **Self-addressing**: the filename stem is the CID v0 of the file's exact bytes
  — the **edge address**, `derive {cid_from, cid_to}`,
  so two signers stating one edge share one filename, each in their own directory.
  Readers reject a file whose raw bytes do not hash to its name
  — tampered or non-canonical files fail before any field is trusted.
- **The cyberlink has its own address.**
  The triple — `derive {cid_from, cid_to, signer}` — is computed from the pair in the file and the signer in the path.
  Both addresses are *derived*, and neither is published:
  the store holds bytes a writer decided to put there,
  not bytes a command computed on the way,
  and writing a link points at its two endpoints only.
  `link add` therefore reports `edge_cid` (which names the file it just wrote) and **not** the cyberlink's CID,
  which addresses nothing until someone publishes its preimage
  — `particle add-link A B S` does that,
  `particle add-edge A B` does it for the pair,
  and the four confirm and deny verbs publish it themselves because they mint it as their target.
  Publishing the pair writes bytes byte-identical to the link file;
  that duplication is accepted rather than desired,
  and is the price of one rule about the store.
  Idempotent throughout,
  so a second signer of the same edge and a convention minting the same pair write nothing new.
- **Triple guard**: the path IS the triple
  — signer in the directory, edge in the filename —
  so a repeat of the same act lands on the same path,
  and `link add` returns the existing record unchanged instead of writing a second file
  — one act, one file, mirroring bostrom's consensus, which rejected a duplicate cyberlink.
  Re-assertion over time is a statement *about* the act (e.g. `convention claimed-at`),
  not a second copy of it.
  The no-op still re-checks the on-disk file's self-addressing and canonical form first,
  so a corrupted file at that path fails loud rather than being reported as a successful repeat.

Example
— the golden pair, the exact bytes of a link file (one line + `\n`, CID `QmUiARbMPT9WNXqvgb2BB9gWFXRiCEqD96AF5xebwNTCTT`):

```json
{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"}
```

The same act's triple record
— not a file `link add` writes, but the preimage an act *about* this cyberlink publishes (CID `QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze` — the cyberlink's derived address):

```json
{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","signer":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}
```

Why JSON and not CSV/NUON: JSON is readable by every language and tool (and natively by nushell);
CSV quoting is not canonical (the same reason nu-multiproof's merkle leaves hash parsed fields, not raw lines).
Certificates are JSON too, for the same reach
— nu-multiproof's `merkle prove`/`verify` speak JSON natively.

## The particle store and text arguments

`particle add` publishes arbitrary content as a self-addressed file:
a string argument or piped content (string or raw bytes) is stored as `particles/<cid>` with its exact bytes,
and the CID comes back.
Idempotent: identical content is one file.
A string argument that names an existing path is opened and its bytes published
— `particle add doc.md` publishes the file, not the six characters `doc.md` —
since a bare-argument caller who writes a path all but always means "publish this file".
A path-shaped argument (a separator or an extension) that names nothing is refused loudly rather than silently published as text,
since that is almost always a typo.
`--literal` is the escape hatch for the rare case a path string is meant as content itself.
Piping is unaffected either way: piped content is always literal, path-shaped or not
— the pipe is itself the deliberate-intent signal.

`--ext` keeps a filename extension on the store file
— `particle add --ext md` writes `particles/<cid>.md`,
so a forge renders it as a document.
The extension is presentation only, never part of the address:
the CID is always the bare 46 characters,
commands that read the store accept only that (`particle cat Qm…` — a filename or path is refused)
and find the file whatever extension it carries.
One CID, one file:
a re-add of existing content under a different extension is a no-op (the first name wins),
and a store holding two files for one CID fails fast on read.
`particle cat` also verifies the bytes hash back to the CID before serving them,
so a tampered store file fails instead of being returned.

`particle cat --optional` returns null when this repo holds no file for the CID,
and still raises on a tampered or ambiguous one.
A graph reader needs that split:
a cyberlink names CIDs and the bytes need not be local,
so absence is ordinary
— but wrapping the plain `cat` in `try`/`catch` to absorb it also swallows the tamper error,
which is the one thing the hash check exists to raise.

Every content argument of a write command (`link add`, `particle add-edge` / `add-link`, all convention verbs) accepts either a CID v0 or content:
a CID is checked against this repo's own store before being used,
anything else resolves to bytes the same way `particle add`'s argument does (an existing path is opened, a path-shaped argument that names nothing is refused, anything else is literal — `--literal` forces literal)
and its CID is used.
So `convention question Qm… "who reviews this?"` publishes the question text and writes the edge in one call,
and `convention pro Qm… argument.md` publishes the file at that path as the argument.
The one ambiguity — content that itself looks like a CID — has a composable escape hatch instead of a flag:
publish it explicitly with `particle add` (which never treats input as an address)
and pass the returned CID.

A CID argument this repo holds no file for is refused by default:
nothing about content-addressing can tell a typo from a deliberate forward reference to bytes held elsewhere,
so refusing is the fail-fast default
and `--allow-missing` is the escape hatch for the legitimate case.
This is a write-time check only
— the read side (`link list`/`touching`/`tally`, `particle cat --optional`) still treats local absence as ordinary,
because a cyberlink names CIDs and the bytes need not be local;
the two sides differ because a reader is looking at a CID someone else already asserted,
while a writer is the one typing it in.

`--signer` publishes content too, since a signer is referenced like any other particle:
a CID v0 is taken as the identity,
and any other string is published under `particles/` as its own bytes, whose CID becomes the signer.
Omitted, it stays this repo's own identity.
This is what gives one repo several signers
— `init` registers exactly one key,
so ad-hoc named identities are the only way to exercise a multi-signer reading (`tally`'s `signers` column, a `confirm-edge` from someone other than the author) without minting keypairs.
Two rules an endpoint has that the signer deliberately does not.
A signer string is **never** opened as a path:
`--signer other.pub` publishes those eight characters, not the key file,
because a signer names an identity rather than a file,
and a path branch would refuse an ad-hoc name carrying a dot or a slash (`agent-1.v2`) as a probable typo;
publishing a key file composes instead
— `particle add other.pub`, then pass the CID.
And a CID here is **not** checked against `particles/` and needs no `--allow-missing`,
because a signer addresses a pubkey file,
which lives in `multiproofs/pubkeys/` and never in the particle store
— this repo's own identity would fail that check.
What the convenience does not do:
a signer minted from content is backed by no key,
so links asserting it are local statements that fail the signer binding at `verify`, `bundle` and `import`.

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

Signer directories are told from the reserved names by form alone:
a root directory named by a CID v0 is a signer's.

A sha256 git backend (`git init --object-format=sha256`) is recommended;
the merkle/certificate layer works on sha1 repos too.
Note GitHub does not host sha256 repos
— Codeberg and plain remotes do.

**Graph home.** The graph home is always `<git-root>/cybergraph/`
— `init` creates it, every command finds it.
Particles are referenced by CID, not path,
so their bytes never need to live under the graph home
— or in the repo at all.
The seal manifest covers only the graph subtree;
a file outside it still gets time-anchored the moment a sealed link mentions its CID,
because showing bytes that hash to an anchored CID extends the anchor to those bytes.
(Attesting a whole repo's files is a different job — use nu-multiproof's `seal` directly for that.)

**The graph home is a closed set.** SPEC section 3 draws the whole tree it may hold
— the signer directories, `particles/`, `certs/`, `seals/`, `exports/`, `imported/`, `receipts/`, and the proof layer's own `multiproofs/` —
and nothing else may sit there, a hand-written `README.md` or `.gitignore` included.
The reason is the seal:
it stages those directories wholesale,
so a file the layout cannot describe would be signed by the signer without any of the checks that make a signature mean something.
`nu-cybergraph strays` is the reading
— one row per path, the directory it sits in, and what that directory is allowed to hold —
and `seal` refuses while it returns anything.
There is no flag to seal past it.
The rule stops where this repo's authority stops:
it recognises `multiproofs/` without policing it,
and it does not reach inside a bundle under `exports/` or `imported/`,
which `verify-bundle` checks as one artifact.

Two refusals carry that,
and they answer different questions.
`seal` enforces the whole set,
because it is the moment those bytes get signed.
Every *reading* enforces the top level alone
— the level that says which layout this is —
and it does so because a reader that cannot tell a foreign graph from an empty one answers `[]` and is believed.
That is not hypothetical:
against a graph still in the superseded `links/<link-cid>.json` shape, the readers reported 301 records as none at exit 0,
and `seal` succeeded, signing a root for links it could not see and certifying none of them.
A graph in that shape is not migrated
— it predates the current format,
and the pre-1.0 rule is that old artifacts are refused rather than converted.

## Conventions (bj002)

The twelve conventions of `bostrom-journal` bj002
— `confirm_edge`/`confirm_link`, `deny_edge`/`deny_link`, `update_edge`, `quote_particle`, `agree_particle`, `disagree_particle`, `pro`, `con`, `question`, `answer_edge`, `author_particle`, `same` —
*encode* an instruction for processing the graph as an ordinary edge.
Concept and rationale live in bj002;
this section is the mechanics.
`nu-cybergraph convention <verb>` writes the edge through the same record path as `link add` (triple guard, self-addressing, signer resolution),
so it takes the same `--signer`/`--repo` controls.
Four further verbs are not among the twelve.
`repeat` publishes the bare edge again:
bj002 names edge repetition beside the conventions but not among them,
because it puts no special CID in the source
— there is no string that would go into `hash()`.
`claimed-at`, `update-particle` and `translation-particle` are this repo's extensions:
`claimed-at` states a time as an edge, the only place this format holds one outside a seal (see time semantics),
`update-particle` states bj002's `update_edge` act — "C replaces B" — about a particle instead of an edge,
which is what a version chain of particles needs and what bj002's edge form cannot express,
and `translation-particle` states that one particle says in another language what another says,
the relation a multilingual corpus is built on and the one neither `same` (two names, one entity) nor `quote-particle` (checkable byte-for-byte) covers.
bj002's set of conventions is open,
which is what permits all three.
Eighteen verbs, twelve conventions:
`confirm` and `deny` are one convention each and two verbs each,
because a name that hides its subject behind an optional argument is what this split removes.

A verb's name and its `op` word name the subject wherever the verb has one
— `confirm-edge`/`confirm-link`, `deny-edge`/`deny-link`, `update-edge`/`update-particle`,
and, with a single possible subject, `agree-particle`, `disagree-particle`, `quote-particle`, `author-particle`, `translation-particle`, `answer-edge`.
The record shape carries the same fact,
but only for a reader that parses the record,
and a CID is opaque:
no tool can tell a particle CID from an edge address at write time unless the preimage already sits in the store.
So the word is the one check that always works.
A verb that names its subject is a gender ending:
redundant against the noun, and exactly what makes a mismatch visible without parsing the sentence
— a writer cannot put a particle verb on an edge address and have it read right.
Where a verb takes any CID on purpose the word stays bare
— `pro`, `con`, `question`, `same`, `claimed-at` —
so a bare word is the signal "any CID".
bj002 spells the same words since 2026-09-02;
the addresses still differ, because bj002 hashes a comma-join where this repo derives from a record,
so no address here has ever matched one there.

Every convention stands on one primitive, the canonical record:
**`convention derive`** takes a flat record,
serializes it canonically
— compact JSON, keys in alphabetical order, values strings only (no nesting: a reference to another record is its CID), exactly one trailing `\n` —
and returns the CID v0 of those bytes, a **derived CID** (reproduce any with `printf '<record>\n' | ipfs add --only-hash --cid-version=0`).
The record form is **an encoding bj002 permits, in a canon that is this repo's own**:
the appendix defines `hash(x, y, …)` as the CID of the arguments comma-joined,
then says that comma-joining is one particular choice and "the arguments can be encoded otherwise — for example, by a canonical serialization of the record into JSON",
under the one condition that the encoding be the same for everyone.
So the alternative is sanctioned and the exact bytes below are ours to pin.
bj002-1 proposed the same records for the journal *text* and was withdrawn as a negative result
— meaning drifts under that conversion;
in code, named fields and IPLD proximity are worth the price.
The appendix's two special cases are just records here:
the edge address is `derive {cid_from: A, cid_to: B}`,
the cyberlink's derived CID is `derive {cid_from: A, cid_to: B, signer: S}`.
This byte format is pinned by `tests/test_convention.nu`, same discipline as the record format
— changing it breaks every derived CID.
The link *file* above IS the pair record under the same rule,
so its self-address and the edge address are one CID.
Acts are addressed by the double and triple alone (bj002 "Fundamentals").
**`particle add-edge A B`** and **`particle add-link A B S`** are the storing half:
they serialize the same two special-case records canonically, store the bytes, and return the same CID `derive` would.
Components rather than a record,
because a hand-built record with a wrong key set serializes fine and yields an address nothing derives
— and nothing reports it, since the file is self-addressed either way.

An instruction lives in the *source* of its edge
— a derived CID such as the CID of `{"op":"deny_edge"}` —
so the source is opaque.
To make it readable, every convention publishes each record it mints
— the instruction and the address records it references —
as self-addressed files under `particles/`:
the record is its own preimage,
so dereferencing the CID yields named fields with the real operand CIDs,
and a text search for an operand's CID finds every record it participates in (bj002 "Reading instructions").
Those files are not sealed directly:
a sealed convention edge names its source CID,
and showing bytes that hash to a sealed CID time-anchors them
— the same rule that anchors any file named by a sealed link.

This table is the spec of the eighteen verbs;
a record in source or target position means the CID of its canonical bytes.
Sixteen rows,
because `agree-particle`/`disagree-particle` and `pro`/`con` are mirror pairs that share a row.
The header of `nu-cybergraph/convention.nu` restates it in the implementation's address-expression notation
— same facts, second notation;
if a shape ever changes, both move together.

| verb | edge written |
|---|---|
| `repeat A B` | `A → B` (the plain edge published again — no instruction record, and not a convention) |
| `confirm-edge A B` | `{"op":"confirm_edge"} → {"cid_from":A,"cid_to":B}` |
| `confirm-link A B S` | `{"op":"confirm_link"} → {"cid_from":A,"cid_to":B,"signer":S}` (a signer's cyberlink) |
| `deny-edge A B` | `{"op":"deny_edge"} → {"cid_from":A,"cid_to":B}` |
| `deny-link A B S` | `{"op":"deny_link"} → {"cid_from":A,"cid_to":B,"signer":S}` (a signer's cyberlink) |
| `update-edge A B C` | `{"cid_from":A,"cid_to":B,"op":"update_edge"} → C` |
| `update-particle B C` | `{"about":B,"op":"update_particle"} → C` (extension, not in bj002; the same act about a particle instead of an edge — a version chain) |
| `quote-particle A B` | `{"about":A,"op":"quote_particle"} → B` |
| `translation-particle A B` | `{"about":A,"op":"translation_particle"} → B` (extension, not in bj002; B says in another language what A says, and the direction records which came first) |
| `agree-particle B` / `disagree-particle B` | `{"op":"agree_particle"\|"disagree_particle"} → B` |
| `pro C B` / `con C B` | `{"about":C,"op":"pro"\|"con"} → B` |
| `question B Q` | `{"about":B,"op":"question"} → Q` |
| `answer-edge B Q A` | `{"cid_from":{"about":B,"op":"question"},"cid_to":Q,"op":"answer_edge"} → A` |
| `author-particle B P` | `{"about":B,"op":"author_particle"} → P` |
| `same P1 P2` | `{"about":P1,"op":"same"} → P2` |
| `claimed-at X T` | `{"about":X,"op":"claimed_at"} → T` (extension, not in bj002; T is an RFC 3339 timestamp published as a file) |

The cyberlink target of `confirm-link` / `deny-link` is the triple record,
and the verb publishes it as it mints it
— so the preimage of the address being confirmed is on disk,
and a reader who has the CID can open it.
The edge target of the two-argument forms is the pair record,
byte-identical to the link file itself and published the same way, by the act that names it.

## Reading the graph

An edge is opaque on purpose: `X → Y` says nothing about what X is.
Reading it back is bj002's "Reading instructions"
— dereference the source,
which works because every convention publishes the record it minted,
so a derived CID has its named fields on disk.
Four commands do that:
three over this signer's own graph, and one over what imported bundles carry.

| command | what it answers |
|---|---|
| `link list` | the whole graph, one row per record: `edge_cid` and `link_cid` (both addresses), the pair as stored, `signer` read off the path, then `op`, `src`, `tgt` — the verb the source declares and the endpoints' own records, where this repo holds them |
| `link touching <cid>` | which links name this CID, and **where**: `role` is `cid_from`, `cid_to`, `signer`, or a dotted path into an instruction's record (`cid_from.about`, `cid_to.cid_from`) |
| `link tally <cid>` | one row per verb and position: how many links say it, and how many distinct signers signed them |
| `link imported` | the same rows as `link list`, but for every link a landed bundle under `imported/` carries — one bundle at a time, each decoded against its own `particles/` and never this repo's |

`role` is the part a CID alone cannot carry.
As `cid_to` of an `update_particle` a particle is the new version;
as `cid_from.about` it is the one being replaced;
as `cid_to.cid_from` it is an endpoint of an edge somebody confirmed;
as `signer` it is the identity that signed the link
— read off the path,
since the signer is the directory and not a field,
so no text search can narrow that case and every link in the signer's directory names them.
A link that names the same CID in two positions comes back twice
— that is a fact about the act, not a duplicate.

`touching` walks **upward** from the CID over the files that name it,
so a query costs the neighbourhood instead of the graph.
An operand's CID is a literal string in every record that mentions it (bj002 again),
so `rg` narrows the candidate files first when it is on PATH
— 0.5s instead of 41s over the journal's 567-link graph.
The search only narrows:
a file that does not contain the string cannot name the CID,
and every file that survives is read, hashed back to its name, and parsed exactly as it would have been.
A file that merely *quotes* a CID in prose is found by the search and dropped by the reading
— search never decides.
`--scan` skips `rg` and reads every record;
same rows,
and `tests/test_read.nu` pins that equality so the fast path cannot become a second implementation.
Without `rg` installed, `--scan` is what runs anyway.

Counts stay separate and are never summed.
Repeats and confirms are two signals
— repeating an edge claims you did the work yourself, confirming leans on whoever did —
so a reader reports two numbers,
and bj002's formula keeps them apart as `f(repeats, confirms, denies, signer_weights, time_decay)`.
Instructions force the distinction:
several signers can propose an update from the one source `{"cid_from":A,"cid_to":B,"op":"update_edge"}`,
and repetitions cannot pick between their versions,
because repeating someone else's update claims you derived it yourself.
Confirmations are what tell the proposals apart.
Summing is a reading policy and belongs to the reader.

The aggregate is not the end of the line
— it is the next particle.
`link tally <cid> | to json | nu-cybergraph particle add` publishes the count as a self-addressed file,
and `link add` hangs it off what it counts:
the aggregate becomes an ordinary vertex others can quote, confirm or deny, without recomputing it.

Two limits, both deliberate.
`list`, `touching` and `tally` read own links only (the signer directories at the graph root)
— an imported bundle is another signer's copy, checked by `verify` against its birth seal,
and mixing it in would silently turn "what this signer said" into "what everyone said",
which is the distinction aggregation rests on;
so `signers` reads 1 in a fresh repo.
`link imported` is the way past that boundary,
and it keeps the distinction rather than dissolving it:
the rows arrive separately, each carrying the `signer` whose claim it is,
so combining them — consensus, cross-signer tallies, dedup — stays a reading policy the caller writes,
the same way `tally` never sums across positions.
And every file the reader opens is hashed back to the CID that names it,
which is the cost that remains:
`link list` reads the whole graph by definition and takes ~20 seconds over 567 links,
and `touching` a CID whose neighbourhood *is* the graph — a signer, named by every link it signed — costs the same.

## Birth certificate

`seal` stages the signer directories plus `certs/ seals/ imported/ receipts/`,
runs nu-multiproof's `seal` (manifest → merkle root → SSH signature → OTS stamp),
snapshots that seal's root statement and signatures under `seals/<root12>/`,
and only then, for every link that has no certificate yet, extracts its inclusion proof and freezes it as `certs/<signer>/<edge>.cert.json`.
The snapshot exists because `multiproofs/tree-root.txt` is overwritten by the next seal
while certificates must verify against the root they were born under.
That it is written *before* the certificates is load-bearing, not incidental:
freezing runs per link and can fail part-way,
and a certificate naming a root whose snapshot was never written can never be verified or exported again
— re-sealing does not repair it,
because the retry mints a different root.
Certificates are never regenerated:
`verify` and `bundle` always use the birth seal, not the repo's current root.

**A repeated seal is not a no-op.** `seals/` is one of the staged directories,
so each seal catalogues the snapshots of every seal before it
— that is the custody continuity above, each root re-attesting the earlier root statements and their signatures.
The consequence is that a seal always changes the manifest and therefore always mints a new root, even when nothing was added:
measured over five consecutive seals with no new link, five distinct roots, `seals/` grown from one directory to five, manifest rows 3, 10, 13, 16, 19
— the jump of seven at the second seal is `certs/`, the signer's certificate directory under it, the first certificate and the `seals/` parent row entering at once,
plus the first snapshot directory and its two files,
then one snapshot directory and its two files per seal after that.
With stamping on, an empty run costs a fresh signature and a calendar round trip,
which is worth knowing against the advice to seal on every append.
A fixpoint would need a snapshot directory named after a root computed from a tree that already contains it
— a hash self-reference, so it is not reachable in practice.

**Which seal is which.** A root says what the tree held, never which seal it was,
so the root statement carries a counter: `multiproof-merkle-v3 <root> <seq> <prev>`,
where `seq` starts at 0 and `prev` is the root that seal superseded (the literal `genesis` for the first, which pairs with `seq 0` and nothing else).
`seal chain` reads every `seals/<root12>/tree-root.txt` in order and requires `seq` to run 0..N with no gap and each `prev` to be the root before it;
a break raises rather than returning a short table,
because a missing snapshot means every certificate born under that root now verifies against nothing.
An absent `seals/` is that same break at full size,
so it raises too
— an empty table there would read as "no seals yet", which is exactly what a wiped directory also looks like.
The counter is checkable *here* and not in a bare nu-multiproof repo, which keeps only the live statement
— this repo keeps every seal it minted,
since a birth certificate must stay verifiable against the seal it was born under.
What it is worth: `multiproofs/` is outside the manifest,
so `seq` is not under the merkle root;
it rests on the signature over the statement and that signature's anchor.
What it buys is that a removed seal stops being invisible.

This is accepted with its cost rather than designed.
Removing `seals/` from the staged set does converge
— a fixpoint at the second seal —
but only while the graph stays untracked by git;
once it is committed the directory re-enters the manifest through `git ls-files`,
because the staged set only ever *adds* and never bounds what the seal covers.
That makes it a fix conditional on a state a shared graph has to leave.
The unconditional lever, gitignoring `seals/`, means the snapshots are never committed and every clone loses them
— and with them the ability to verify or export any link born under those roots.

What the manifest covers, precisely:
every git-tracked file under the graph home except `multiproofs/`,
which nu-multiproof excludes as derived output.
So the registered pubkey is *not* under the seal
— it is tracked by git and carries no manifest row.
Its authority comes from the signature it validates, not from inclusion.

**Committing is yours; the wording is only proposed.** `seal` never commits
— message, scope and timing are decisions it has no context for —
and `--propose-commit` does not change that:
it writes the commit into the prompt with `commandline edit` and stops,
so nothing runs until you read it, edit it and press enter.
What it removes is the other failure, a seal landing under "wip" or split over three commits,
which makes the log useless for the one question it should answer:
when was this root sealed, and what froze under it.
The subject is `seal: graph catalogued at merkle root <first 8 hex>`
— truncated,
because the whole 64 push everything else off a `git log --oneline` line while the first 8 already say which root this is.
The body states the root CID, the merkle root, the signer CID, how many certificates froze and of which kind, the `seals/<root12>` snapshot they verify against, and the bundle with its endorsement anchor
— the content anchor never appears,
because `seal` always suppresses it.
The pathspec is what the seal owns end to end: the staged directories plus `multiproofs/`, added wholesale rather than file by file,
since a seal also *deletes* in there
— nu-multiproof clears a signature over bytes the regeneration changed —
and a deletion appears in no result field.
`particles/` is deliberately absent, the same way `seal` does not stage it:
publishing the bytes a link names is your own act,
and it has its own commit (below).

**The store is committed before the seal, and `seal` refuses while it is not.** `link add` publishes its text endpoints as particles,
so the store grows out of stating an edge rather than out of a `particle add` someone typed
— and the manifest is git-tracked files,
so those files enter a root only if they were in the index first.
Sealed the other way round, the link is signed and frozen while its endpoint is catalogued by nothing,
and nothing said so:
the seal succeeded,
and only a reader coming back later found a certificate proving an edge whose bytes were never attested.
So `seal` refuses while the graph names a store file git does not track,
and `particle uncommitted` is the reading it refuses on
— one row per store file git does not hold clean,
each marked `reachable` (a link here names its CID, directly or as an operand inside a record it names), `orphan` (published, named by nothing yet) or `missing` (tracked, gone from the working tree).
`--propose-commit` writes the `git add` and `git commit` for the reachable ones into the prompt unrun,
exactly as `seal --propose-commit` does.
An orphan is never staged and no flag includes it:
a file no link names is not in the graph,
so committing it is a plain `git add` rather than this command's business.
The escape hatch is `seal --allow-untracked-particles`, which seals without those bytes;
it never reaches a name under `particles/` that is no address at all,
because the closed-set refusal below runs before it and no flag touches that one.

**Time semantics.** The record carries no timestamp:
a time inside the record would fork the same act into different CIDs per recording moment,
and it would still prove nothing.
The one provable time is the birth seal's OTS anchor over the *signature*, reported as `signer.endorsed`:
"the signer endorsed this no later than Bitcoin block N".
A link is an assertion by a signer,
so that is the claim
— and it is the one that has to survive a key compromise,
since after revocation at time R only a signature datable before R still means anything.
An SSH signature carries no time field of its own,
so without this anchor a signature made today fitted a year-old bundle and nothing on disk contradicted it.
`verify` reports the endorsement of the record's signer, matched by key material through the same pubkey table as the signer binding;
each custody layer carries its custodian's the same way.
`absent` means the endorsement is real but undated, not that it is missing.
There is deliberately **no second anchor**:
nu-multiproof can also stamp the root statement, dating the record's bytes without saying who asserted them,
and `seal` here always passes `--no-content-anchor` to suppress it.
Two anchors would not say which one dates the statement
— both true, neither derived from the other on disk —
leaving every reader to decide which is the time, what a disagreement means, and whether verification needs one or both.
One anchor leaves none of those open,
and upstream's `ots` field is dropped from the verify record rather than reported as permanently `absent`.
The price is accepted knowingly:
content-time is derived through the signature,
so it inherits every way SSH verification can rot over decades,
where a content anchor stays a bare sha256 compare.
The earliest provable bound is set by the *first* seal,
which is why certificates freeze
— later seals only add newer roots.
Provable granularity equals seal frequency,
so seal on every append (a seal costs one signature plus a free OTS stamp per signature for the whole batch).
A fresh stamp reports `pending` until Bitcoin confirms (hours/days);
any later seal in the origin repo upgrades it,
but an already-exported bundle keeps its pending stamp until `ots upgrade` is run on it by hand.
A signer who wants to *claim* a time states it as an ordinary edge
— `convention claimed-at <cid> <rfc3339>` —
optional, per-signer, and unproven.
A provable *lower* bound ("created no earlier than") would need a recent Bitcoin block hash embedded in the record
— deliberately out of v1.

**Signer identity.** A signer is the CID v0 of its public-key *file bytes*,
and the spec pins one canonical encoding for those bytes: `<type> <base64>` plus a trailing newline
— no comment, no extra whitespace.
Identity-by-bytes keeps verification trivially reproducible (hash the file, compare — no SSH-format parsing in the trust path);
the canonical form keeps that hash stable and moves the one unavoidable parse to the boundary
— `init` canonicalizes the key at registration,
`import`/`verify` reject a bundle whose pubkey file is not canonical.
The key comment is deliberately excluded:
it is mutable metadata (`user@host` drifts across machines and re-saves)
and would silently fork one key into several identities.
Nothing replaces it: this toolchain stores no human label for a key anywhere.
Renaming a registered pubkey file is the operator's own affair,
and nothing reads the result
— pinned by `tests/test_roundtrip.nu` "a renamed pubkey file still exports a verifiable bundle".
One keypair is one signer
— distinct identities need distinct keypairs.
Which of them is *this* graph's identity is the key the checkout signs with
— `user.signingKey`, the same key `seal` signs the root with, or the `--key` an export was given —
matched to a registered file by its canonical bytes, never by a filename.
So `multiproofs/pubkeys/` may hold more than one key without ambiguity:
verification reads every valid signature over a root,
so a key registered beside the configured one can add a signature and never takes authorship.
`init --co-signer <key>.pub` is how one joins
— a plain `init` refuses to grow a trust list it did not start,
because a key must never be trusted by accident.

**Authorship.** A repo is one signer's graph, sealed by that signer's key:
the root signature covers every catalogued record,
so individual records carry no signature.
Authorship travels in the certificate:
a valid signature over the root statement plus the merkle path proves the signer attested this exact record.
Verification additionally checks the **signer binding**
— the signer named by the record's path must be the CID of a pubkey that validly signed the root statement.
Without that check, anyone could re-seal someone else's record under their own key and the signature would still verify
— against the wrong identity.
The binding is also what gives the signer directory its authority:
the path enters the signed root,
so a pair refiled under another directory names a signer who never signed that root,
or breaks its merkle proof outright.
The binding says *who* signed;
`signer.endorsed` says *when they signed*
— the same lookup by key material, run against the seal's endorsement anchors (see time semantics).

## Bundles, import, provenance

`bundle <edge-cid>` assembles the portable artifact set in the layout nu-multiproof pins under "Verifying without the origin repo":
the record at its `<signer>/<edge>.json` path, the certificate, the birth seal's root statement + signatures, the signer pubkeys, the OTS bundles committing to that root,
and — by default — a copy under `particles/` of whichever of the record's two ends this repo holds a file for.
When more than one signer holds the edge, `--signer` names whose act leaves
— several candidates without it are refused, never guessed.
Without those bytes an importer has the address of the instruction a link states (e.g. `{"op":"agree_particle"}`) but not its preimage,
and can only decode the edge's meaning by scanning `particles/` across every repo it can reach;
`--links-only` drops the birth bundle to the record + certificate alone.
(`--links-only` is a no-op re-exporting an imported link: that bundle is copied unchanged, particles included, per the read-only-foreign-authority rule below.)
Anyone verifies it offline with no access to the origin repo:
`verify-bundle <dir>` is that command,
and it needs nothing else — no repo, no registered key, no network.
It returns the same record `verify` returns for a link held locally,
because it is the same check
— `verify <edge-cid>` runs the same checker over the repo itself, once per copy held,
pointing it at `certs/<signer>/<edge>.cert.json` and the birth seal's snapshot under `seals/`;
`--signer` narrows to one act.
`import` also verifies, but it is the stronger act
— it needs an initialized repo with a registered pubkey and it writes a custody receipt,
so it is what you run to *take* a bundle, not to *check* one.

`import <bundle>` verifies first (merkle structure, signature, record self-addressing, canonical pubkey form, signer binding, and every custody layer — below)
and refuses invalid bundles loudly.
A valid bundle lands intact under `imported/<signer-cid>/<edge-cid>/`
— it remains the link's authority for authorship and birth time forever,
and the copy is read-only: re-export passes it along unchanged.
Import also writes a **custody receipt** at `receipts/<author-cid>/<edge-cid>.receipt.json`, outside the read-only copy and mirroring the link layout
— the author directory plus the edge name address the act as unambiguously as the cyberlink CID,
and keying by the edge alone would collide the moment a second author's copy of the same edge lands.
The receipt is `{cid_from, cid_to, signer, custodian, received_at, files, prev, handoff}`
— the first three spell the cyberlink out instead of addressing it,
so `convention derive` over them recovers its CID while the receipt itself needs nothing external to say what it is about.
A receipt is not content-addressed,
so a lone derived CID here would name an act whose preimage lives somewhere else;
spelling the components out removes that dependency rather than satisfying it
— a stranger holding one custody layer reads the act from the receipt's bytes, with no store to consult and no CID to trust.
`import` publishes no preimage for the cyberlink it lands:
taking custody of an act is not speaking about one,
so the custodian's store gains that file only when the custodian decides to speak about the cyberlink (`particle add-link`).
`files` is a path+sha256 manifest of the birth-bundle files as received,
`prev` is the sha256 of the previous custody layer's receipt file (null for the first custodian),
and `handoff` is the sha256 of the handoff the bundle arrived by (null when it arrived without one).
The next `seal` catalogues the receipt and freezes its inclusion proof beside it as `receipts/<author>/<edge>.receipt.cert.json`
— the same freeze rule as birth certificates:
the first seal sets the earliest provable custody bound.

`bundle` on an imported link **re-exports** it:
the foreign bundle copied unchanged,
plus this repo's custody layer appended under `custody/<n>-<signer12>/`.
A layer is a proof bundle in the birth layout
— the receipt at its `receipts/` path, its frozen proof at the layer root, the sealing root statement + signatures + pubkeys + OTS —
so the same machinery verifies it:
structure, signature, custodian binding (the receipt's `custodian` must be the CID of a validly-signing pubkey), `files` against the actual birth bytes, and the `prev` chain with contiguous layer numbering.
The chain is what makes a dissemination path provable *in order*:
layer *i*'s receipt commits to layer *i−1*'s receipt,
so a stranger holding only the bundle can check "A authored it, then B held it no later than block K_B, then C no later than K_C"
— provenance grows in layers without touching the original certificate,
and each receipt stays constant-size (re-listing prior layers would grow the chain quadratically).

**Handoff.** Custody proves *holding*;
without more, direction ("B → C") is only an inference from who held what.
`bundle --to <signer-cid>` makes it a signed claim:
a handoff file `<edge-cid>.handoff.json` — `{schema, cid_from, cid_to, signer, from, to, receipt, handed_at}` — plus a detached SSH signature,
written at the bundle root (author) or inside the sender's custody layer (custodian).
The act is stated, not addressed, exactly as in a receipt:
`cid_from`/`cid_to`/`signer` are the cyberlink's three components,
so the file says which act it moves without a store to dereference a CID in,
and `convention derive` over them recovers the address anyway.
`signer` is the act's author and does not move;
`from` and `to` are the holders this transfer is between,
and they coincide with `signer` only for the author's own handoff.
It is the one artifact signed directly rather than through a seal,
because the bundle leaves at export time, before any later seal could catalogue it.
`schema` is the constant `"cybergraph-handoff-v2"` and comes first,
so the signed bytes open with a tag naming what they are:
every SSH signature this toolchain makes is under the single `file` namespace,
so a signature over untagged bytes could be replayed into any other context where the key signs bytes.
Verification requires the token byte-exact
— the JSON counterpart of nu-multiproof's one-line root statement.
`receipt` pins the sha256 of the sender's receipt (null for the author),
tying the claim to the exact chain state handed over;
the recipient's receipt hashes the handoff back (its `handoff` field),
so once the recipient seals, the sender's claim can no longer be stripped from the chain.
Verification binds the signature to the sender's identity (a validly-signing pubkey whose CID is `from` — the handoff twin of the signer binding)
and checks the seam:
the previous holder's handoff must name the next layer's custodian,
and `import` refuses a bundle handed to someone else
— its own custody layer could never verify.
The refusal is a fail-fast for honest importers, not a boundary against an interceptor (see the limits below).
A handoff is optional (an open export names no recipient) and is a claim of *sending*, not a proof of delivery.

Three honest limits.
The custody bounds are upper bounds:
the chain proves each receipt existed before the next custodian's seal, not when a hop actually happened.
A receipt pins the birth files byte-for-byte,
so mutating an imported copy — including running `ots upgrade` inside it — breaks the `files` commitment of every receipt taken over those bytes;
upgrade stamps in your own repo's `multiproofs/`, never inside `imported/`.
And until the recipient seals, a handoff is just a file in the bundle:
whoever holds the bytes can strip it (with its signature) and import the bundle as an open one,
erasing the sender's directional claim
— the seal, not the misaddressed-import refusal, is what makes a handoff permanent.

## Dependencies

- [nu-multiproof](https://github.com/nushell-prophet/nu-multiproof) as a live sibling checkout at `../nu-multiproof`
  — resolved in exactly one place, the `nu-cybergraph/_deps/` shims;
  edit them if your checkout lives elsewhere.
  Not a submodule: the two repos are co-developed and a pin would lag.
- `rg` ([ripgrep](https://github.com/BurntSushi/ripgrep)), optional and only for `link touching`/`link tally`:
  it narrows which files the reader opens.
  Absent, the same commands read every record and return the same rows
  — nothing depends on it for correctness, which is why it can be optional at all.
- `git` and `ssh-keygen`, nothing else:
  per-file, per-directory and root CIDs are all computed in pure nushell,
  so no `ipfs` CLI is needed.

## Testing

Requires [nutest](https://github.com/vyadh/nutest) as a live sibling checkout at `../nutest`
— the same convention as the nu-multiproof dependency, and the path `toolkit.nu` imports.

```nushell no-run
use toolkit.nu *; main test
```

Tests run fully offline: the OTS stamp is the only network call the seal path makes,
and there are two ways past it.
Most tests pass `--no-stamp` and skip stamping entirely;
a few pass `--response-file` instead,
which takes the calendar's answer from a local fixture and so reaches a real stamp with no network
— that is where a status reads `pending` rather than `absent`.
The two flags are alternatives and `seal` refuses them together,
since `--no-stamp` would leave the fixture read by nobody.
A calendar can only ever answer `pending`
— confirmation happens later, in a block —
so `anchored` is reached by building a Bitcoin attestation offline, the one OTS byte format this suite writes for itself.
CIDs need no external call at all, and the rest of the OTS internals are exercised by nu-multiproof's own suite.
