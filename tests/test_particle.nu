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
def "particle add opens an argument that names an existing path" [] {
    let tmp = $in.tmp
    let file = $tmp | path join "doc.md"
    "hello" | save --raw $file
    let expected = "hello" | into binary | cid-v0
    assert equal (particle add $file --repo $tmp) $expected
    assert equal (open --raw $file | particle add --repo $tmp) $expected
}

@test
def "particle add --literal publishes a path string as its own bytes" [] {
    let tmp = $in.tmp
    let file = $tmp | path join "doc.md"
    "hello" | save --raw $file
    assert equal (particle add $file --repo $tmp --literal) ($file | into binary | cid-v0)
}

@test
def "particle add refuses a path-shaped argument that names nothing" [] {
    let tmp = $in.tmp
    assert error {|| particle add ($tmp | path join "missing.md") --repo $tmp }
    # A regular string sharing no path shape (no separator, no extension) is
    # never mistaken for a missing path — it just publishes as content.
    assert equal (particle add "missing" --repo $tmp) ("missing" | into binary | cid-v0)
}

# A dotfile name (`.env`, `.gitignore`) has no separator and, by `path
# parse`'s own reckoning, no extension either — the leading dot is read as
# the whole stem. Without its own check this class of typo would silently
# publish the dotfile name as content instead of erroring.
@test
def "particle add refuses a dotfile-shaped argument that names nothing" [] {
    let tmp = $in.tmp
    assert error {|| particle add ".env" --repo $tmp }
}

@test
def "particle add accepts a path-shaped string when piped" [] {
    let tmp = $in.tmp
    let file = $tmp | path join "doc.md"
    "hello" | save --raw $file
    assert equal ($file | particle add --repo $tmp) ($file | into binary | cid-v0)
}

# A broken symlink still names a path a caller meant to read — `path exists`
# alone would miss it (it resolves the target, which is gone), so the guard
# checks `--no-symlink` instead.
@test
def "particle add refuses a dangling symlink argument" [] {
    let tmp = $in.tmp
    let link = $tmp | path join "dangling"
    ^ln -s ($tmp | path join "does-not-exist") $link
    assert error {|| particle add $link --repo $tmp }
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

# The absence a reader may legitimately meet: a cyberlink names CIDs, and the
# bytes need not be local.
@test
def "particle cat --optional returns null for a CID the store does not hold" [] {
    assert equal (particle cat $A --repo $in.tmp --optional) null
}

# The point of the flag: absence turns into null, tampering still raises. Under
# a bare try/catch the two would be one outcome, and the hash check would be
# worth nothing to a reader who has to handle absence.
@test
def "particle cat --optional still rejects a tampered file" [] {
    let tmp = $in.tmp
    let root = $in.root
    let cid = particle add "cyber" --repo $tmp
    "evil" | save --force --raw (particle-path $root $cid)
    assert error {|| particle cat $cid --repo $tmp --optional }
}

@test
def "particle cat --optional still fails on two files for one CID" [] {
    let tmp = $in.tmp
    let root = $in.root
    let cid = particle add "cyber" --repo $tmp
    "cyber" | save --raw (particle-path $root $cid --ext md)
    assert error {|| particle cat $cid --repo $tmp --optional }
}

@test
def "link add resolves text endpoints to published files" [] {
    let r = link add "cyber" "bostrom" --repo $in.tmp --signer $N | get record
    assert equal $r.cid_from ("cyber" | into binary | cid-v0)
    assert equal $r.cid_to ("bostrom" | into binary | cid-v0)
    assert equal (open --raw (particle-path $in.root $r.cid_to)) "bostrom"
}

@test
def "link add opens a text endpoint that names an existing path" [] {
    let tmp = $in.tmp
    let root = $in.root
    let file = $tmp | path join "doc.md"
    "hello" | save --raw $file
    let r = link add $file "bostrom" --repo $tmp --signer $N | get record
    assert equal $r.cid_from ("hello" | into binary | cid-v0)
    assert equal (open --raw (particle-path $root $r.cid_from)) "hello"
}

@test
def "link add --literal publishes a path-shaped endpoint as its own bytes" [] {
    let tmp = $in.tmp
    let file = $tmp | path join "doc.md"
    "hello" | save --raw $file
    let r = link add $file "bostrom" --repo $tmp --signer $N --literal | get record
    assert equal $r.cid_from ($file | into binary | cid-v0)
}

@test
def "link add refuses a path-shaped endpoint that names nothing" [] {
    let tmp = $in.tmp
    assert error {|| link add ($tmp | path join "missing.md") "bostrom" --repo $tmp --signer $N }
}

# Validation before side effects: resolving a content endpoint publishes it, so
# a repo that cannot name a signer has to fail before the first file lands.
# It used to publish both endpoints and only then raise from `own-signer`,
# leaving orphan files for a link that was never written.
@test
def "link add publishes nothing when the repo has no signer identity" [] {
    let tmp = $in.tmp
    assert error {|| link add "cyber" "bostrom" --repo $tmp }
    assert not ((particles-dir $in.root) | path exists)
}

@test
def "link add passes CID endpoints through without publishing anything" [] {
    link add $A $B --repo $in.tmp --signer $N --allow-missing | ignore
    # only links/ was written: no particles dir means no file was minted
    assert not ((particles-dir $in.root) | path exists)
}

# The default this repo's own resolve-particle enforces: a CID it holds no
# file for is very likely a typo, not a deliberate reference to bytes held
# elsewhere, and content-addressing gives no way to tell the two apart —
# --allow-missing is the escape hatch for the legitimate case.
@test
def "link add refuses a CID endpoint this repo holds no file for" [] {
    let tmp = $in.tmp
    let err = try { link add $A $B --repo $tmp --signer $N; null } catch {|e| $e.msg }
    assert ($err != null) "an unpublished CID endpoint was accepted with no flag"
    assert ($err | str contains $A) $"the refusal does not name the missing CID: ($err)"
    assert ($err | str contains "allow-missing") $"the refusal does not name its own escape hatch: ($err)"
    # ...and the escape hatch actually works, same repo, no other change
    link add $A $B --repo $tmp --signer $N --allow-missing | ignore
}

@test
def "convention verbs refuse a CID operand this repo holds no file for" [] {
    let tmp = $in.tmp
    assert error {|| convention agree $A --repo $tmp --signer $N }
    convention agree $A --repo $tmp --signer $N --allow-missing | ignore
}

# The check and its escape hatch both walk the whole address expression, not
# just its top-level leaf — confirm's cyberlink form nests a signer CID
# inside the target record, and answer nests a question record two levels
# inside the source. Either bare CID missing locally must refuse without the
# flag, and --allow-missing must reach it wherever it sits.
@test
def "allow-missing reaches an operand nested inside the address expression" [] {
    let tmp = $in.tmp
    assert error {|| convention confirm $A $B $N --repo $tmp --signer $N }
    convention confirm $A $B $N --repo $tmp --signer $N --allow-missing | ignore

    assert error {|| convention answer $A "q" "a" --repo $tmp --signer $N }
    convention answer $A "q" "a" --repo $tmp --signer $N --allow-missing | ignore
}

@test
def "convention verbs resolve text arguments before hashing" [] {
    let q = convention question $A "why?" --repo $in.tmp --signer $N --allow-missing | get record
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
