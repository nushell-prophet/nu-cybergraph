# Why: the submodules export everything so tests can `use` any helper; this file names the public commands.
# A named list flattens the namespace, so each file's subcommands go through an inline module of the same name,
# and `main` is imported outside it: inside a wrapper module it would surface as `seal seal`, not `seal`.
export use init.nu [ main ]
module particle { export use particle.nu [ add add-edge add-link cat uncommitted ] }
export use particle
export use strays.nu [ main ]
module link { export use link.nu [ add imported list tally touching ] }
export use link
module order { export use order.nu [ backfill list ] }
export use order
# Why: the eighteen convention verbs would fill the completion list of `nu-cybergraph`,
# so a caller imports them on their own: `use nu-cybergraph/convention.nu`.

# Exported so a reader can compute any address by hand: the edge address
# `derive {cid_from: A, cid_to: B}`, the cyberlink's derived CID
# `derive {cid_from: A, cid_to: B, signer: S}`, a candidate instruction
# source (bj002 appendix, "Reading instructions"), or the act a receipt or a handoff states.
# Why: it is the canon of the whole format, not of the conventions alone,
# so a reader who checks a bundle needs no convention import to get it.
export use _derive.nu [ derive ]
export use seal.nu [ main ]
module seal { export use seal.nu [ chain ] }
export use seal
export use bundle.nu [ main ]
export use import.nu [ main ]
export use verify.nu [ main ]
export use verify-bundle.nu [ main ]
