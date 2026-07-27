# Create link records in a signer's repo.

use _repo.nu graph-root
use _fs.nu list-files
use _record.nu [link-bytes link-cid]
use _layout.nu [links-dir link-path]
use _particle.nu [resolve-particle]
use _deps/cid-v0.nu [cid-v0]

# Derive the repo's own signer identity: the CID of its registered pubkey.
# With several pubkeys registered the choice is the signer's — require --signer.
def own-signer-cid [root: path]: nothing -> string {
    let pubs = list-files ($root | path join multiproofs pubkeys) --suffix ".pub"
    match ($pubs | length) {
        0 => (error make {msg: "no pubkey registered — run `nu-cybergraph init` first"})
        1 => (open --raw ($pubs | first) | into binary | cid-v0)
        _ => (error make {msg: "multiple pubkeys registered — pass --signer explicitly"})
    }
}

# Write a new link record to links/<cid>.json, named by its own content address.
# An endpoint is any content-addressed file; its CID is the CID v0 of its bytes.
# Both endpoints accept a CID or content: a non-CID argument is published as a
# file under particles/ and its CID is linked (see _particle.nu).
@example "link two files by the CIDs of their bytes" { link add QmUQUHEmv651XCBhiWUQpx2zf4PDts1aXL324ZFyV4QZPF QmW9519sfmW2MvDb4TU4dKtiFAXm1UPDvE7JrMaBjprVHp }
@example "publish two texts as files and link them" { link add "cyber" "bostrom" }
export def add [
    cid_from: string # source vertex: a CID v0, or content to publish as a file
    cid_to: string # target vertex: a CID v0, or content to publish as a file
    --signer: string # Signer CID (default: CID of the single registered pubkey)
    --repo: path # Target repo root (default: git root of current directory)
]: nothing -> record {
    let root = graph-root $repo
    let rec = {
        cid_from: (resolve-particle $root $cid_from)
        cid_to: (resolve-particle $root $cid_to)
        signer: (if $signer != null { $signer } else { own-signer-cid $root })
    }
    let cid = link-cid $rec
    mkdir (links-dir $root)
    let out = link-path $root $cid
    # The record IS the triple, so file existence IS the triple guard: one act,
    # one CID, one file — mirroring bostrom's consensus, which rejected a repeat
    # cyberlink. Why no --reassert: a repeat is byte-identical, so there is
    # nothing new to store; re-assertion over time is a statement ABOUT the act
    # (e.g. `convention claimed-at`), not a second copy of it.
    if ($out | path exists) {
        error make {msg: $"signer already asserted this edge: ($cid)"}
    }
    link-bytes $rec | save --raw $out
    {cid: $cid path: $out record: $rec}
}
