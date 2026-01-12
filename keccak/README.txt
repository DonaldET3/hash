Opal Keccak
for Unix

This program computes hashes of files to verify data integrity.

By default, the program computes the hash of a stream of input data from
standard input.

In list mode, the program takes an Opal manifest file stream from standard input
and adds or replaces Keccak hashes in each file record before outputing the
manifest file to standard output.

In update mode, the program takes an Opal manifest file stream from standard
input and checks modification times before replacing Keccak hashes in each file
record or adds a hash to a record with no hash before outputing the manifest
file to standard output.

In check mode, the program reads a manifest file, looks for Keccak hashes to
check, and outputs each file name followed by either ": OK" or ": FAILED"
depending on whether the hash matches, ": NO FILE" if the file cannot be found,
": NO HASH" if there is no associated Keccak hash, or ": OLD HASH" if the
associated Keccak hash is for a file that has a different modification time and
the hash does not match.

The quiet option inhibits reports of OK files.

options_
h: print help and exit
l: list mode
u: update mode
c: check mode
s: hash length in bits (multiple of 8, up to 528, default: 512)
r: number of rounds (at least 12, default: 24)
q: quiet

keccak-alg.txt describes the variation of the Keccak algorithm that is used in
this program

oumnf-keccak.txt describes the extensions that are made to the manifest format
to support Keccak hashes

