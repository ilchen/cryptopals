### Challenge 67. Rainbow tables: space efficient recovery of passwords from their hashes
In addition to the properties of second preimage resistance and target collision-resistance, which we looked at in
Challenges 53 and 54, another popular use for hash functions relies on their one-way property.
Namely  given `y = H(x)` it should be computationally infeasible to derive `x`. This property of cryptographic
hash functions is used in identification and login protocols such as those found in various Unix systems.

In the simplest form the identification system will use a table such as one shown below to verify that the user logging in 
indeed knows their password.

| user-id | Hash |
|---------|------|
| id<sub>1</sub>| H(password<sub>1</sub>) |
| id<sub>2</sub>| H(password<sub>2</sub>) |
| ...|...|
| id<sub>n</sub>| H(password<sub>n</sub>) |

Not storing the password in plaintext presumably makes it harder to figure out someone's password by coming
in possession of the passwords file. Assuming passwords are `n` characters long where each character is one of the 95
printable ascii characters, one would think that an attacker getting hold of such a file will need to do an exhaustive
search on each user's password to discover it, which requires an effort of O(95<sup>n</sup>) per password.

For such a primitive system an active attacker can even pre-compute hashes for all `n` characters passwords and store them
in an dictionary table `L`. Then, every time the attacker intercepts a user's login password hash, they are able to immediately
look up their password in table `L`. This is known as an _offline dictionary attack_. The total effort required to build it
is O(95<sup>n</sup>). The total space will be 95<sup>n</sup> · (32 + n) bytes. For 8 character passwords hashed with
SHA-256 this will take up around 32 PiB, which is not practical. Can we do better? It turns out we can thanks to 
Hellman’s basic time-space tradeoff, which was later evolved into what is now known as _rainbow tables_.


...................

...................

...................


Assuming a system that uses 5 character long ascii passwords, given the following three MD4 hashes:
```
C89F2A956A8C8AE1F3D2B547BDA4498F
27300880ECECAAF7FF6705F10C6BC35F
8D850E3B2E28233C24432FCF45372B74
```
build a rainbow table and recover the original passwords. The base64 encodings of the original passwords are (no peeking please):
```
clx4IDw=
KTlpMGg=
Il44LC4=
```

Remember that the probability of the rainbow table containing the password you are looking for is around 66% so you
might need to build a couple of different rainbow tables to recover them.
