# Seal the neuron repo and freeze birth certificates for newborn links.
#
# A birth certificate is the inclusion proof extracted from the FIRST seal
# that catalogued the link, frozen in certs/ and never regenerated. Its OTS
# anchor is the link's earliest provable time bound; later seals only add
# newer roots and must not touch existing certificates.

use _repo.nu repo-root
use _deps.nu [seal merkle]

# `seal` in the body is nu-multiproof's seal; this wrapper stages the
# cybergraph files, runs it, then freezes certificates and the root snapshot.
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --key: path # SSH private key (default: from git config user.signingKey)
    --no-stamp # Skip OTS timestamping (stamping is the point — tests only)
    --no-root-cid # Skip IPFS root CID (per-file CIDs are still computed pure-nu)
]: nothing -> record {
    let root = repo-root $repo

    # Fail fast BEFORE multiproof's seal mutates anything (it writes the
    # manifest and root statement before signing): signing needs the signer's
    # pubkey registered in multiproofs/pubkeys/. Registration is deliberate —
    # it establishes the neuron identity — so seal points to init instead of
    # registering as a side effect.
    let registered = glob ($root | path join multiproofs pubkeys *.pub)
    if ($registered | is-empty) {
        let hint = if $key != null { $" --pubkey ($key)" } else { "" }
        error make {msg: $"no pubkey registered in multiproofs/pubkeys/ — run `nu-cybergraph init($hint)` first"}
    }
    if $key != null {
        let pub = if ($key | str ends-with ".pub") { $key } else { $"($key).pub" }
        if ($pub | path exists) {
            # Compare key material (type + base64), ignoring comments
            let material = open --raw $pub | str trim | split row " " | first 2 | str join " "
            let known = $registered | any {|f|
                (open --raw $f | str trim | split row " " | first 2 | str join " ") == $material
            }
            if not $known {
                error make {msg: $"($pub) is not registered in multiproofs/pubkeys/ — run `nu-cybergraph init --pubkey ($pub)` first"}
            }
        }
    }

    # Stage the cybergraph dirs: the manifest walks `git ls-files`, so an
    # untracked newborn link would silently miss its own seal. certs/ and
    # seals/ hold artifacts of PREVIOUS seals — cataloguing them makes each
    # seal also attest the certificates issued so far (custody continuity).
    let stage = [links certs seals]
        | each {|d| $root | path join $d }
        | where {|d| ($d | path exists) and (ls $d | is-not-empty) }
    if ($stage | is-not-empty) {
        ^git -C $root add -- ...$stage
    }

    let sealed = if $key != null {
        seal --repo $root --key $key --no-stamp=$no_stamp --no-root-cid=$no_root_cid
    } else {
        seal --repo $root --no-stamp=$no_stamp --no-root-cid=$no_root_cid
    }
    let root_hex = $sealed.merkle_root

    # Freeze birth certificates for links that don't have one yet.
    let certs_dir = $root | path join certs
    mkdir $certs_dir
    let newborn = glob ($root | path join links *.json)
        | where {|f|
            not (($certs_dir | path join $"(($f | path parse).stem).cert.nuon") | path exists)
        }
    for f in $newborn {
        let proof = merkle prove ($f | path relative-to $root) --repo $root
        mv $proof ($certs_dir | path join $"(($f | path parse).stem).cert.nuon")
    }

    # Snapshot this seal's root statement + signatures. multiproofs/tree-root.txt
    # is overwritten by every seal, but certificates verify against the root
    # they were born under — the snapshot is what `bundle` exports later.
    let snap = $root | path join seals ($root_hex | str substring 0..11)
    if not ($snap | path exists) {
        mkdir $snap
        cp ($root | path join multiproofs tree-root.txt) $snap
        glob ($root | path join multiproofs tree-root.txt.*sig) | each {|s| cp $s $snap }
    }

    {sealed: $sealed newborn: ($newborn | length) snapshot: $snap}
}
