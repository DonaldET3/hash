Opal SHA-2
for Unix

This program computes hashes of files to verify data integrity.

By default, the program computes the hash of a stream of input data from
standard input.

In list mode, the program takes an Opal manifest file stream from standard input
and adds or replaces SHA-2 hashes in each file record before outputing the
manifest file to standard output.

In update mode, the program takes an Opal manifest file stream from standard
input and checks modification times before replacing SHA-2 hashes in each file
record or adds a hash to a record with no hash before outputing the manifest
file to standard output.

In check mode, the program reads a manifest file, looks for SHA-2 hashes to
check, and outputs each file name followed by either ": OK" or ": FAILED"
depending on whether the hash matches, ": NO FILE" if the file cannot be found,
": NO HASH" if there is no associated SHA-2 hash, or ": OLD HASH" if the
associated SHA-2 hash is for a file that has a different modification time and
the hash does not match.

The quiet option inhibits reports of OK files.

options_
h: print help and exit
l: list mode
u: update mode
c: check mode
s: hash length in bits (multiple of 8, up to 512, default: 512)
r: number of rounds (at least 32, default: 96)
w: word size in bits (32, 64, or 128, default: 128)
q: quiet

future options
t: threads (default: 1)

sha2-alg.txt describes the variation of the SHA-2 algorithm that is used in
this program

oumnf-sha2.txt describes the extensions that are made to the manifest format
to support SHA-2 hashes

