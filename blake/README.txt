Opal BLAKE
for Unix

This program computes hashes of files to verify data integrity.

By default, the program computes the hash of a stream of input data from
standard input.

In list mode, the program takes an Opal manifest file stream from standard input
and adds or replaces BLAKE hashes in each file record before outputing the
manifest file to standard output.

In update mode, the program takes an Opal manifest file stream from standard
input and checks modification times before replacing BLAKE hashes in each file
record or adds a hash to a record with no hash before outputing the manifest
file to standard output.

In check mode, the program reads a manifest file, looks for BLAKE hashes to
check, and outputs each file name followed by either ": OK" or ": FAILED"
depending on whether the hash matches, ": NO FILE" if the file cannot be found,
": NO HASH" if there is no associated BLAKE hash, or ": OLD HASH" if the
associated BLAKE hash is for a file that has a different modification time and
the hash does not match.

The quiet option inhibits reports of OK files.

options
h: print help and exit
l: list mode
u: update mode
c: check mode
s: hash length in bits (multiple of 8, up to 512, default: 512)
r: number of rounds (at least 12, default: 16)
w: word size in bits (64 or 128, default: 128)
p: word permutation (odd number 1 - 15, default: 5)
q: quiet

future options
t: threads (default: 2)

blake-alg.txt describes the variation of the BLAKE algorithm that is used in
this program

oumnf-blake.txt describes the extensions that are made to the manifest format to
support BLAKE hashes

