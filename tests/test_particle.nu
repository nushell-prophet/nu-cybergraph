use std/assert
use std/testing *

use ../nu-cybergraph/particle.nu
use ../nu-cybergraph/link.nu
use ../nu-cybergraph/convention.nu
use ../nu-cybergraph/_derive.nu [derive]
use ../nu-cybergraph/_layout.nu [particles-dir particle-path]
use ../nu-cybergraph/_deps/cid-v0.nu [cid-v0]

# Same fixture CIDs as test_convention.nu; plain --repo dir, fixed signer,
# so everything runs offline with no git/ssh/init.
const A = "QmQXupHE6VPzpoBTivNXAAGwigJE68n4TeVUSxYnFL78GV"
const B = "Qmc9pm5gQqDwJMiFTmFEuTxRhSy5Cn2yt7NZh1LrxmMhSi"
const N = "QmddrVz92VH3LqT2i7uXeK4AVh6LyU7zjDiLbSdChPsULr"

@before-each
def setup []: nothing -> record {
    let tmp = mktemp --directory
    {tmp: $tmp root: ($tmp | path join cybergraph)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp
}

@test
def "particle add stores the exact bytes under their own CID" [] {
    let root = $in.root
    let cid = particle add "cyber" --repo $in.tmp
    assert equal $cid ("cyber" | into binary | cid-v0)
    assert equal (open --raw (particle-path $root $cid) | into binary) ("cyber" | into binary)
}

@test
def "particle add is idempotent and accepts piped string or binary" [] {
    let tmp = $in.tmp
    let first = particle add "cyber" --repo $tmp
    assert equal (particle add "cyber" --repo $tmp) $first
    assert equal ("cyber" | particle add --repo $tmp) $first
    assert equal (0x[63 79 62 65 72] | particle add --repo $tmp) $first
}

@test
def "particle add refuses ambiguous or missing input" [] {
    let tmp = $in.tmp
    assert error {|| "piped" | particle add "argument" --repo $tmp }
    assert error {|| particle add --repo $tmp }
}

# The escape hatch for content that looks like a CID: particle add never
# treats its input as an address, so the CID string itself becomes content.
@test
def "particle add publishes a CID-shaped string as content" [] {
    let tmp = $in.tmp
    let cid = particle add $A --repo $tmp
    assert not equal $cid $A
    assert equal $cid ($A | into binary | cid-v0)
}

@test
def "particle add --ext stores under <cid>.md and returns the bare CID" [] {
    let tmp = $in.tmp
    let cid = particle add "# doc" --ext md --repo $tmp
    assert equal $cid ("# doc" | into binary | cid-v0)
    assert ((particle-path $in.root $cid --ext md) | path exists)
}

# One CID, one file: the extension is a name, not part of the address, so a
# re-add under a different extension is a no-op and the first name wins.
@test
def "particle add is idempotent across extensions" [] {
    let tmp = $in.tmp
    let bare = particle add "cyber" --repo $tmp
    assert equal (particle add "cyber" --ext md --repo $tmp) $bare
    assert equal (ls (particles-dir $in.root) | length) 1
    assert ((particle-path $in.root $bare) | path exists)
}

@test
def "particle add rejects a malformed extension" [] {
    let tmp = $in.tmp
    assert error {|| particle add "x" --ext ".md" --repo $tmp }
    assert error {|| particle add "x" --ext "m d" --repo $tmp }
    assert error {|| particle add "x" --ext "a/b" --repo $tmp }
}

@test
def "particle cat returns exact bytes by bare CID, whatever the extension" [] {
    let tmp = $in.tmp
    let bare = particle add "cyber" --repo $tmp
    let ext = particle add "# doc" --ext md --repo $tmp
    assert equal (particle cat $bare --repo $tmp) "cyber"
    assert equal (particle cat $ext --repo $tmp) "# doc"
}

@test
def "particle cat refuses anything but a bare CID" [] {
    let tmp = $in.tmp
    let cid = particle add "# doc" --ext md --repo $tmp
    assert error {|| particle cat $"($cid).md" --repo $tmp }
    assert error {|| particle cat ([particles $cid] | path join) --repo $tmp }
}

@test
def "particle cat fails on a file that is not in the store" [] {
    assert error {|| particle cat $A --repo $in.tmp }
}

@test
def "particle cat fails fast on a store with two files for one CID" [] {
    let tmp = $in.tmp
    let root = $in.root
    let cid = particle add "cyber" --repo $tmp
    "cyber" | save --raw (particle-path $root $cid --ext md)
    assert error {|| particle cat $cid --repo $tmp }
}

@test
def "particle cat rejects a tampered store file" [] {
    let tmp = $in.tmp
    let root = $in.root
    let cid = particle add "cyber" --repo $tmp
    "evil" | save --force --raw (particle-path $root $cid)
    assert error {|| particle cat $cid --repo $tmp }
}

@test
def "link add resolves text endpoints to published files" [] {
    let r = link add "cyber" "bostrom" --repo $in.tmp --signer $N | get record
    assert equal $r.cid_from ("cyber" | into binary | cid-v0)
    assert equal $r.cid_to ("bostrom" | into binary | cid-v0)
    assert equal (open --raw (particle-path $in.root $r.cid_to)) "bostrom"
}

@test
def "link add passes CID endpoints through without publishing anything" [] {
    link add $A $B --repo $in.tmp --signer $N | ignore
    # only links/ was written: no particles dir means no file was minted
    assert (not ((particles-dir $in.root) | path exists))
}

@test
def "convention verbs resolve text arguments before hashing" [] {
    let q = convention question $A "why?" --repo $in.tmp --signer $N | get record
    assert equal $q.cid_from (derive {about: $A, op: "question"})
    assert equal $q.cid_to ("why?" | into binary | cid-v0)
    assert equal (open --raw (particle-path $in.root $q.cid_to)) "why?"
}

@test
def "convention verbs resolve args embedded in derived sources" [] {
    let q = convention quote "source text" "text" --repo $in.tmp --signer $N | get record
    let src_cid = "source text" | into binary | cid-v0
    assert equal $q.cid_from (derive {about: $src_cid, op: "quote"})
    assert equal (open --raw (particle-path $in.root $src_cid)) "source text"
}
