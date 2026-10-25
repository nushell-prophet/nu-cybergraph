# nu-cybergraph

A local cybergraph on a git backend:
content-addressed link records between IPFS CIDs.

Each link has a proof of its author and a proof of its birth time,
built on [nu-multiproof](https://github.com/nushell-prophet/nu-multiproof).

🚧 Proof of concept, agent-written, barely tested
— do not treat as secure.

## Concept

**Cybergraph** is a data structure that is made of cyberlinks.
Each **cyberlink** is a signed record of this form:

```
{
    cid_from: Qm1
    cid_to: Qm2
    signer: Qm3
}
```

`cid_from` and `cid_to` are the CIDs of the two particles that are connected.
The pair `cid_from → cid_to` is an **edge** of the cybergraph, directed from `cid_from` to `cid_to`.

A **particle** is one name for two things:
a vertex of the graph and the bytes of the file under its CID.
The CID (content identifier) of any file can be computed:
it is an IPFS hash of the bytes of the file.
A file becomes a particle of the cybergraph
when its CID is used in an edge of a cyberlink.

A **signer** is an agent (for example, a human, an AI) that created and signed the cyberlink.
The `signer` field is the CID of the public key of the signer (Qm3),
so the signer can be referenced like any CID.

A cyberlink is a statement by a signer:
"these two particles are connected".

`nu-cybergraph` is a Nushell module for working with cybergraphs on a git backend.
The design goal is cheap portability of each link:
a signer can give one link to another party,
and the recipient can verify who signed it and when.
The signer does not sign each record,
and does not send the whole graph.
The mechanism is a **birth certificate**:
the signer signs one merkle root for each seal,
and an OpenTimestamps (OTS) stamp dates that signature in a Bitcoin block.
The inclusion proof of each link is frozen from the first seal that listed it.

## Origins

@mastercyb is the author of the initial idea of Cybergraph.
It first appeared in [2017](https://github.com/cyberia-to/go-cyber/blob/c0bb4755c5c2955ca98cd6e7374e0d0f4a0d2a51/cyberd%20Protocol%20Whitepaper.md).
He continues his work on the concepts and the implementation in https://github.com/cyberia-to/.

In this repo I develop a lighter local implementation.
The concept behind this module is described in `bostrom-journal`, issue [bj002](https://github.com/cyber-prophet/bostrom-journal/blob/master/bj002.md).

## Quick start

```nushell no-run
use nu-cybergraph/

nu-cybergraph init                       # create <repo>/cybergraph/ and register your SSH key
nu-cybergraph init --co-signer k.pub     # register one more key, whose signature over a root is also read
nu-cybergraph particle add "any text"    # publish content as particles/<cid>, get the CID
nu-cybergraph particle add-edge Qm…A Qm…B      # publish the record of an edge address, so a later act can name it
nu-cybergraph particle add-link Qm…A Qm…B Qm…S # the same for the derived CID of a cyberlink
nu-cybergraph derive {cid_from: Qm…A, cid_to: Qm…B} # compute a derived CID; writes nothing
nu-cybergraph particle cat Qm…           # the exact bytes of a stored file, by its bare CID
nu-cybergraph particle uncommitted       # store files that git does not have, and whether the graph names them
nu-cybergraph strays                     # files under the graph home that the layout does not describe
nu-cybergraph link add Qm…from Qm…to     # write a link; an argument that is not a CID is published first
nu-cybergraph link list                  # the whole graph as a table, each edge with the verb it states
nu-cybergraph link touching Qm…          # which links name this CID, and in which position
nu-cybergraph link tally Qm…             # per verb and position: how many links, how many signers
nu-cybergraph link imported              # the same reading over the links of imported bundles
nu-cybergraph order list                 # this signer's run of links, oldest first
nu-cybergraph seal                       # sign the root, stamp the signature, freeze new certificates
nu-cybergraph seal --propose-commit      # also put the git commit for the seal in the prompt, not run
nu-cybergraph seal --external-signer     # the root is signed on another device: run, sign there, run again
nu-cybergraph seal chain                 # all seals, oldest first; refuses a gap
nu-cybergraph bundle Qm…edge --out x     # a portable bundle in x/, with the particles that the ends name
nu-cybergraph bundle Qm…edge --out x --links-only # the record and its proofs only
nu-cybergraph bundle Qm…edge --to Qm…signer # also a signed handoff that names the recipient
nu-cybergraph import path/to/bundle      # verify a bundle, keep it under imported/, write a custody receipt
nu-cybergraph verify Qm…edge             # check every copy held here, against its birth seal
nu-cybergraph verify-bundle path/to/bundle # check a received bundle with no repo of your own

use nu-cybergraph/convention.nu          # the convention verbs are a separate import
convention question Qm… "who reviews this?" # publish the question and link it to Qm…
```

## Link record format

A link is one small file.
The format is fixed byte for byte,
so an independent implementation computes the same CIDs.
The reference is `nu-cybergraph/_record.nu`;
`tests/test_record.nu` pins the golden bytes and CIDs.

- **The file holds the pair, the path holds the signer.**
  The file is `<signer-cid>/<edge-cid>.json`
  and holds exactly two string fields, `cid_from` and `cid_to`.
  The path goes into the signed root,
  so a file that moves into the directory of another signer breaks its own proof.
- **One canonical form.**
  Compact JSON, keys in the order of their UTF-8 bytes, exactly one `\n` at the end.
  All values are CID v0 strings (`Qm` + 44 characters),
  so no JSON escape can occur.
- **The name is the hash.**
  The file name is the CID of the exact bytes of the file
  — the edge address.
  So two signers that state one edge share one file name, each in their own directory.
  A reader refuses a file whose bytes do not hash to its name,
  before it trusts any field.
- **One act, one file.**
  The same act written again goes to the same path.
  `link add` then returns the record that is already there and writes nothing.
  This mirrors Bostrom, which refused a duplicate cyberlink.
  The command still checks the file on disk first,
  so a corrupted file fails loudly.
- **No time in the record.**
  A time inside the record would split one act into a different CID for each moment.
  And that time would prove nothing.
  Time comes from the seal (see "Time").

The golden pair, the exact bytes of a link file (CID `QmUiARbMPT9WNXqvgb2BB9gWFXRiCEqD96AF5xebwNTCTT`):

```json
{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp"}
```

The record of the same act with its signer
— the derived CID of the cyberlink, `QmRyRXXRM7ztFTPiyXjDtra9ND2oU64iE2jcydwubW17Ze`:

```json
{"cid_from":"QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF","cid_to":"QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp","signer":"QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"}
```

`link add` does not write this second record:
the store holds only bytes that a writer decided to publish,
not bytes that a command computed on the way.
`particle add-link A B S` publishes it,
and the confirm and deny verbs publish it, because they name it.

Why JSON:
every language and tool reads it, and Nushell reads it natively.
CSV quoting has no single canonical form.

## Particles

`particle add` stores content as `particles/<cid>`, with its exact bytes, and returns the CID.
The same content is always one file.

A text argument can be a path or text:

- An argument that names an existing file publishes the file:
  `particle add doc.md` publishes the document, not the six characters `doc.md`.
- An argument that looks like a path (a separator or an extension) but names nothing is refused.
  It is almost always a typo.
- Anything else is published as text.
  `--literal` forces text.
- Piped content is always published as it is.

Every write command (`link add`, the convention verbs) takes the same arguments:
a CID, or content that it publishes first.
So `convention question Qm… "who reviews this?"` publishes the question and writes the edge in one call.
Content that itself looks like a CID is the one ambiguous case:
publish it with `particle add`, then pass the CID that it returns.

A write refuses a CID that this repo holds no file for,
because a typo and a reference to bytes held elsewhere look the same.
`--allow-missing` permits the second case.
A reader does not refuse:
a cyberlink names CIDs, and the bytes do not need to be local.
`particle cat --optional` returns null for a missing file,
but still fails on a file whose bytes do not hash to its CID.

`--ext md` keeps an extension on the store file, so a forge shows it as a document.
The extension is never part of the address,
and the commands that read the store take only the bare CID.

## Signers

A signer is the CID of the bytes of its SSH public key file,
in one canonical form: `<type> <base64>` and a newline.
So anyone can verify an identity by a hash, with no parse of the SSH format.
The key comment is left out on purpose:
`user@host` changes between machines,
and it would split one key into several identities.
`init` writes the canonical form,
and `import` and `verify` refuse a key file in any other form.

One key pair is one signer.
The identity of the graph is the key that signs its seals (`user.signingKey`),
matched to a registered key file by its bytes, never by its name.
`init --co-signer` registers one more key:
its signature over a root counts, but it never takes authorship.
A plain `init` does not add keys to a list that it did not start.

Two flags choose another signer for a write:

- `--signer` names a registered key, by its CID or by its file.
  A link binds to that signer only if that key also signs the seal.
- `--keyless-signer` publishes a name as a particle and uses its CID as the signer.
  This gives one repo several signers with no new key pairs, for a try of a multi-signer reading.
  Such links stay local:
  they fail the signer check in `verify`, `bundle` and `import`.

## Graph home

```
cybergraph/
  <signer-cid>/<edge-cid>.json                   # link records: the pair in the file, the signer in the path
  particles/<cid>[.ext]                          # published content and records
  order/<signer-cid>/<edge-cid>.order.json       # the position of each link in the run of its signer
  certs/<signer-cid>/<edge-cid>.cert.json        # birth certificates, frozen
  seals/<root-hex-12>/                           # a copy of each root statement and its signatures
  imported/<signer-cid>/<edge-cid>/              # bundles of other signers, kept unchanged
  receipts/<author-cid>/<edge-cid>.receipt.json  # custody receipts for imported links
  multiproofs/                                   # the nu-multiproof machinery: manifest, keys, OTS
```

`init` creates the graph home at `<repo>/cybergraph/`.
A command finds the nearest `cybergraph/` from the current directory up to the git root,
so one git repo can hold one graph per project.
A directory whose name is a CID v0 belongs to a signer.

The graph home is a closed set:
nothing else may sit in it, not even a `README.md`.
The seal signs these directories whole,
so a file that the layout does not describe would be signed with no check.
`strays` lists such files,
and `seal` refuses while the list is not empty.
Every reading command also refuses an unknown layout at the top level.
A reader that cannot tell a foreign layout from an empty graph answers `[]`, and the answer is believed.

A sha256 git backend (`git init --object-format=sha256`) is recommended;
sha1 works too.
GitHub does not host sha256 repos;
Codeberg and plain remotes do.

## Conventions

A published edge `A → B` has an address,
so a signer can refer to it as to any other CID.
To issue an instruction, a signer puts a special CID
— such as `{"op":"deny_edge"}` or `{"about":A,"op":"quote_particle"}` —
in the source of an ordinary edge.
`op` is the convention word,
and `about` is the subject of the instruction.
Each instruction is itself an edge with an address,
so it can in turn be confirmed or denied with the same conventions.
This recursion makes the set of conventions open.
bj002 gives the conventions and the reasons for each.

The suffix of a convention word names the kind of its subject:
`_particle` names a file, `_edge` names an edge, `_link` names a cyberlink.
A bare word (`pro`, `con`, `question`, `same`) names any CID.
So a mistake such as `agree_particle` on an edge address shows in the word itself.
A CID is opaque,
and the word is the only check that always works.

The verbs, as `convention <verb>` writes them
(a record in place of a CID means the CID of its canonical bytes):

- `repeat A B` — `A → B`, the same edge again; not a convention, it states the same thing personally
- `confirm-edge A B` — `{"op":"confirm_edge"} → {"cid_from":A,"cid_to":B}`
- `confirm-link A B S` — `{"op":"confirm_link"} → {"cid_from":A,"cid_to":B,"signer":S}`
- `deny-edge A B` — `{"op":"deny_edge"} → {"cid_from":A,"cid_to":B}`
- `deny-link A B S` — `{"op":"deny_link"} → {"cid_from":A,"cid_to":B,"signer":S}`
- `update-edge A B C` — `{"about":{"cid_from":A,"cid_to":B},"op":"update_edge"} → C`
- `quote-particle A B` — `{"about":A,"op":"quote_particle"} → B`
- `agree-particle B` — `{"op":"agree_particle"} → B`
- `disagree-particle B` — `{"op":"disagree_particle"} → B`
- `pro X B` — `{"about":X,"op":"pro"} → B`
- `con X B` — `{"about":X,"op":"con"} → B`
- `question X Q` — `{"about":X,"op":"question"} → Q`
- `answer-edge X Q R` — `{"about":{"cid_from":{"about":X,"op":"question"},"cid_to":Q},"op":"answer_edge"} → R`
- `author-particle X P` — `{"about":X,"op":"author_particle"} → P`
- `same P1 P2` — `{"about":P1,"op":"same"} → P2`

Three verbs are extensions of this repo, not in bj002:

- `update-particle B C` — `{"about":B,"op":"update_particle"} → C`: C replaces B, for a version chain of files
- `translation-particle A B` — `{"about":A,"op":"translation_particle"} → B`: B says in another language what A says
- `claimed-at X T` — `{"about":X,"op":"claimed_at"} → T`: a time that the signer claims, as an RFC 3339 file; not a proof

The verbs write through the same path as `link add`,
and take the same `--signer`, `--keyless-signer` and `--repo` flags.

Every address comes from one primitive, the canonical record.
`nu-cybergraph derive` takes a flat record of strings,
writes it as compact JSON with sorted keys and one `\n`,
and returns the CID of those bytes.
A nested record is first replaced by its CID.
`printf '<record>\n' | ipfs add --only-hash --cid-version=0` gives the same CID,
and so does bj002, which defines a derived CID by the same bytes.
`tests/test_convention.nu` pins this format.

## Reading the graph

A CID is opaque:
`X → Y` says nothing about what X is.
bj002 gives the way to read it back:
dereference the source and read its content.
That works only if the record is published as a file,
so every convention verb publishes each record that it computes.

- `link list` — the whole graph, one row per link, with the verb that the source states and the records of both ends
- `link touching <cid>` — which links name this CID, and in which `role`
- `link tally <cid>` — per verb and position: how many links, and how many different signers
- `link imported` — the same rows as `link list`, for the links that imported bundles carry

`role` tells what a CID alone cannot.
As `cid_to` of an `update_particle`, a particle is the new version;
as `cid_from.about`, it is the replaced version;
as `signer`, it is the identity that signed the link.

`touching` starts from the CID and reads only the files that name it,
so a query costs the neighbourhood, not the whole graph.
When `rg` is installed, it first narrows the files to read.
It only narrows:
the reader still hashes and parses every file that remains.
`--scan` skips `rg`, and `tests/test_read.nu` pins that both ways give the same rows.

The counts stay separate and are never summed.
Repetition and `confirm_edge` are different signals,
and work distinguishes them.
Repetition needs work:
only then does the signer state the same thing.
`confirm_edge` is support from a signer who did not do the work.
bj002 keeps them apart as `f(repeats, confirms, denies, signer_weights, time_decay)`:
the exact formula is a read policy, and it belongs to the reader.

`list`, `touching` and `tally` read only the links of this repo.
An imported bundle is the statement of another signer,
and a silent mix would turn "what this signer said" into "what everyone said".
`link imported` reads the bundles,
and each row keeps the signer whose claim it is.

A result can itself become a particle:
`link tally <cid> | to json | nu-cybergraph particle add` publishes the count,
and others can then quote, confirm or deny it.

## Seal and birth certificate

`seal` does these steps:

1. It refuses if the graph home holds strays,
   or if the graph names a file in `particles/` that git does not track.
2. It numbers the new links of the signer (see "Order").
3. nu-multiproof builds the manifest and its merkle root, signs the root with SSH, and stamps the signature with OTS.
4. It copies the root statement and its signatures to `seals/<root12>/`.
5. For each link with no certificate, it freezes the inclusion proof as `certs/<signer>/<edge>.cert.json`.
   It freezes the proof of each new position and receipt in the same way, beside the file.

The copy in `seals/` is necessary,
because the next seal overwrites the live root,
but a certificate must verify against the root it was born under.
So step 4 comes before step 5:
a certificate that names a root with no copy can never verify again.
A certificate is frozen at birth and never made again.

The manifest covers every git-tracked file under the graph home, except `multiproofs/`.
So the store must be committed before the seal.
Otherwise the link is signed, but the bytes it names enter no root, and nothing warns about it.
`particle uncommitted` shows each store file that git does not hold:
`reachable` (a link names it), `orphan` (nothing names it yet) or `missing` (tracked, but not on disk).
`particle uncommitted --propose-commit` puts the commit for the reachable files in the prompt.

`seal` never commits:
the message, the scope and the time of a commit are the decision of the signer.
`--propose-commit` puts the commit command in the prompt and does not run it,
so the signer reads it, edits it and presses enter.
The subject is `seal: graph catalogued at merkle root <first 8 hex>`.

**Seal chain.**
Each root statement carries a counter: `multiproof-merkle-v3 <root> <seq> <prev>`.
`seq` starts at 0,
and `prev` is the root that this seal replaced (`genesis` for the first one).
`seal chain` reads all copies in `seals/`,
and refuses a gap instead of a shorter list:
a missing copy means that the certificates born under that root verify against nothing.

A seal is never a no-op.
`seals/` is in the manifest,
so each seal also covers the copies of all the seals before it,
and always gives a new root.
With OTS on, a seal with nothing new still costs a signature and a request to the calendar.

**Order.**
`link add` writes a position for each link in `order/`,
and the seal turns it into a number in the run of the signer.
The run is the analogue of the account sequence in Bostrom:
with no gaps, it proves that the record of a signer is complete,
so nobody can hide a link from a copy.
The number is not in the record bytes,
because a number there would split one shared edge address per signer.
`link add` writes a time, not a number:
two checkouts that merge give interleaved times,
and the seal sorts them into the real order.

## Time

The record has no timestamp.
The one provable time is the OTS anchor of the birth seal over the *signature*.
`verify` reports it as `signer.endorsed`:
"the signer endorsed this no later than Bitcoin block N".
A link is a statement by a signer, so this is the claim.
It is also the claim that must survive a key compromise:
after a revocation at time R, only a signature dated before R still has a meaning.

There is deliberately no second anchor over the content.
With two anchors, each reader would have to decide which one is the time.
One anchor leaves no such question.

The first seal sets the earliest provable bound,
which is why certificates freeze.
So the time is only as precise as the seals are frequent:
seal often.
A new stamp is `pending` until Bitcoin confirms it, after hours or days;
a later seal in the origin repo upgrades it.
A signer who wants to claim a time states it as an edge:
`convention claimed-at <cid> <rfc3339>`.

## Authorship

The root signature covers every record in the manifest,
so a record carries no signature of its own.
The certificate carries authorship:
a valid signature over the root plus the merkle path proves that the signer attested this exact record.

`verify` also checks the **signer binding**:
the signer that the path of the record names must be the CID of a key that validly signed the root.
Without this check, anyone could seal the record of another signer under their own key,
and the signature would verify against the wrong identity.

## Bundles, import, provenance

`bundle <edge-cid>` collects what a stranger needs to check one link:
the record at its path, its certificate and position,
the keys, the root statement and signatures of the birth seal, and the OTS proofs.
By default, it also copies the particles that the ends of the link name,
so the recipient can read the instruction, not only its CID.
`--links-only` leaves them out.
When more than one signer holds the edge, `--signer` chooses;
`bundle` never guesses.

`verify-bundle <dir>` checks a bundle offline,
with no repo, no registered key and no network.
`verify <edge-cid>` runs the same check over each copy that this repo holds,
always against the birth seal, never against the current root.

`import <bundle>` takes a bundle.
It refuses a bundle that fails any check:
merkle structure, signature, self-addressing, canonical key form, signer binding, or any custody layer.
There are no partial imports.
A valid bundle goes unchanged into `imported/<signer>/<edge>/`
and stays the authority for authorship and birth time.
The copy is read-only.

**Custody.**
`import` also writes a custody receipt, `receipts/<author>/<edge>.receipt.json`:
`{cid_from, cid_to, signer, custodian, received_at, files, prev, handoff}`.
The first three fields state the act itself,
so a stranger who holds only the receipt reads the act from it.
`files` is a sha256 manifest of the bundle as received,
and `prev` is the hash of the receipt of the previous holder.
The next seal freezes the receipt, like a certificate.

`bundle` on an imported link re-exports it:
it copies the foreign bundle unchanged
and adds the custody layer of this repo under `custody/<n>-<signer12>/`.
Each receipt points to the one before it,
so a stranger can check the path of the bundle in order:
"A wrote it, then B held it no later than block K_B, then C no later than K_C".

**Handoff.**
Custody proves that a holder had the bundle, but not who sent it to whom.
`bundle --to <signer-cid>` adds a signed claim:
`<edge-cid>.handoff.json` with a detached SSH signature.
It is the one file signed directly, not through a seal,
because the bundle leaves before a later seal can cover it.
Its first key is `"schema": "cybergraph-handoff-v2"`,
so the signed bytes name what they are.
Every signature of this toolchain uses one SSH namespace,
and untagged bytes could be replayed in another context.
The receipt of the recipient hashes the handoff,
and `import` refuses a bundle handed to another signer.
A handoff claims that the sender sent the bundle;
it does not prove delivery.

### Limits

- Custody times are upper bounds.
  The chain proves that each receipt existed before the seal of the next holder,
  not when a transfer happened.
- A receipt pins the bytes of the bundle,
  so any change to an imported copy breaks it.
  `ots upgrade` inside `imported/` is such a change:
  upgrade the stamps in your own `multiproofs/` only.
- Until the recipient seals, a handoff is only a file.
  Whoever holds the bundle can remove it and import the bundle as an open one.
  The seal makes a handoff permanent;
  the refusal in `import` only protects honest importers from a mistake.

## Dependencies

- [nu-multiproof](https://github.com/nushell-prophet/nu-multiproof), carried in this repo at `nu-multiproof/`.
  `nu-cybergraph/_deps/` is the one place that resolves it,
  so a clone holds the exact version that this repo was tested with.
- `git` and `ssh-keygen`.
  CIDs are computed in pure Nushell, so no `ipfs` CLI is necessary.
- `rg` ([ripgrep](https://github.com/BurntSushi/ripgrep)), optional:
  it makes `link touching` and `link tally` faster, with the same rows.

## Testing

The tests need [nutest](https://github.com/vyadh/nutest) as a sibling checkout at `../nutest`.
The suite of nu-multiproof runs from `nu-multiproof/` and needs a `nutest` link there too (gitignored).

```nushell no-run
nu toolkit.nu test
```

The tests run offline.
The OTS stamp is the only network call of a seal:
most tests pass `--no-stamp`,
and a few pass `--response-file`, which reads the answer of the calendar from a local file.
CIDs need no external call.
