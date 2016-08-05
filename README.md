# :chestnut: tamanegi 玉ねぎ
> Experiment in creating .onion names

Computes a valid Tor `.onion` hostname and `private_key` pair.

Can brute force a specific prefix for the hostname hash if desired.

Tamanegi not designed to be the most performant or featureful, but rather
something with code that is easy to compile and understand (as I am only writing it to
better understand the topic myself!).

**This is an unfinished work in progress.**

## Usage

    Usage of tamanegi:
      -c	continuously search for multiple matches
      -n num
        	quit after finding num matches (implies -c)
      -output directory
        	write keys to filesystem directory
      -p prefix
        	search for hashes matching prefix
      -t threads
        	number of simultaneous hashing threads (default $NUM_CPU)

## How are .onion names generated?
The Tor Wiki has [this to say on the subject][source]:

> If you decide to run a hidden service Tor generates an ​RSA-1024 keypair. The
> .onion name is computed as follows: first the ​SHA1 hash of the ​DER-encoded
> ​ASN.1 public key is calculated. Afterwards the first half of the hash is
> encoded to ​Base32 and the suffix ".onion" is added. Therefore .onion names can
> only contain the digits 2-7 and the letters a-z and are exactly 16 characters
> long.

[source]: https://trac.torproject.org/projects/tor/wiki/doc/HiddenServiceNames

### Brute forcing onion names

Generating new RSA keys is computationally expensive.

Rather, we generate a RSA keypair and enumerate the public key exponent through
all possibilities (odd numbers E<sub>min</sub>-E<sub>max</sub>) and examine the
resulting .onion hash. If a successful partial collision is found, the resulting
key is then verified and exported if valid.

This technique is copied from [shallot] and others.

See also: https://www.thc.org/papers/ffp.html

### Other .onion name colliders

 - [shallot]: classic edition.
 - [eschalot]: more sophisticated wordlist generation/matching.
 - [scallion]: uses OpenCL for GPU hashing (Mono/.NET).

[shallot]:  https://github.com/katmagic/Shallot
[eschalot]: https://github.com/ReclaimYourPrivacy/eschalot
[scallion]: https://github.com/lachesis/scallion
