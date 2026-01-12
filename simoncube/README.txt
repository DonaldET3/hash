Opal SimonCube
for Unix

This program computes hashes of files to verify data integrity.

By default, the program computes the hash of a stream of input data from
standard input.

In list mode, the program takes an Opal manifest file stream from standard input
and adds or replaces SimonCube hashes in each file record before outputing the
manifest file to standard output.

In update mode, the program takes an Opal manifest file stream from standard
input and checks modification times before replacing SimonCube hashes in each
file record or adds a hash to a record with no hash before outputing the
manifest file to standard output.

In check mode, the program reads a manifest file, looks for SimonCube hashes to
check, and outputs each file name followed by either ": OK" or ": FAILED"
depending on whether the hash matches, ": NO FILE" if the file cannot be found,
": NO HASH" if there is no associated SimonCube hash, or ": OLD HASH" if the
associated SimonCube hash is for a file that has a different modification time
and the hash does not match.

The quiet option inhibits reports of OK files.

options_
h: print help and exit
l: list mode
u: update mode
c: check mode
s: hash length in bits (multiple of 8, default: 512)
i: initialization rounds (at least 16, default: 16)
r: rounds per block (at least 8, default: 16)
b: block size in bytes (1 - 128, default: 32)
f: finalization rounds (at least 32, default: 32)
q: quiet

simoncube-alg.txt describes the mixture of the Simon and CubeHash algorithms
that is used in this program

oumnf-simoncube.txt describes the extensions that are made to the manifest
format to support SimonCube hashes

