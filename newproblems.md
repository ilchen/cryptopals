I've been missing a continuation of Cryptopals after I finished Set 8. Here I make a humble attempt at starting to define new problems and solving them. 
I hope you enjoy them.

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

Not storing a password in plaintext presumably makes it harder to figure it out by coming
in possession of the passwords file. Assuming passwords are `n` characters long where each character is one of the 95
printable ascii characters, one would think that an attacker getting hold of such a file will need to do an exhaustive
search on each user's password to discover it, which requires an effort of O(95<sup>n</sup>) per password.

For such a primitive system an active attacker can even pre-compute hashes for all `n` characters passwords and store them
in an dictionary table `L`. Then, every time the attacker intercepts a user's login password hash, they are able to immediately
look up their password in table `L` by the hash. This is known as an _offline dictionary attack_. The total effort required to build 
such a table is O(95<sup>n</sup>). The total space will be 95<sup>n</sup> · (32 + n) bytes. For 8 character passwords hashed with
SHA-256 this will take up around 32 PiB, which is not practical. Can we do better? It turns out we can thanks to 
Hellman’s basic time-space trade-off, which was later evolved into what is now known as _rainbow tables_.

The idea of a rainbow table is fairly simple. Say your passwords occupy space &#x3A1; and their hashes space &#x3D2;.
The hash function h, e.g. SHA-256, then maps elements in &#x3A1; to those in &#x3D2; &mdash; h: &#x3A1; &#x2192; &#x3D2;.
Note that the size of &#x3D2; (2<sup>256</sup> bits for SHA-256) is larger than the size of &#x3A1; (< 2<sup>64</sup> for 8 character passwords).
The first thing to do to build a rainbow table is to come up with a function that provides an inverse mapping, i.e.
a mapping from elements in &#x3D2; to &#x3A1;. Let's call this function y: &#x3D2; &#x2192; &#x3A1;. The simplest way to construct it 
is to take the minimum number of the most-significant bits from a SHA-256 hash that are required to represent 8 ascii symbolds and
convert these bits into ascii symbols.

The next step is to come up with a way to make multiple such y functions, each one behaving differently. Let's assign them
an index so that we refer to them as y<sub>i</sub>. How do you make them behave differently from the original y function
in the previous paragraph? You can generate a unique random pad for each i and then define y<sub>i</sub>(hash) as:

`y(i, hash) := to_ascii_array(most_significant_bits_of(hash) ^ random_pads[i])`

Or you can make it even simpler and do something along the following lines:

`y(i, hash) := to_ascii_array(to_long(most_significant_bits_of(hash) + i))`

this way no storage for random pads is called for.

With our y<sub>i</sub>: &#x3D2; &#x2192; &#x3A1; ready let's define another group of functions called f<sub>i</sub> as
follows: f<sub>i</sub>(x) := g<sub>i</sub>(hash(x)). If you've been paying attention, you've noticed that f<sub>i</sub>
map elements in &#x3A1; to elements in &#x3A1; (e.g. from 8 character ascii passwords to 8 character ascii passwords).


The next thing we do is define the number of rows (l) and columns (τ) in our rainbow table `L`. If |&#x3A1;| = N,
then we define l = N<sup>2/3</sup> and τ = N<sup>1/3</sup>. You might want to take a ceiling of these exponentiations to ensure that l·τ >= N.
Now we are ready to build our rainbow table `L`. For each row you generate a random 8 character password and then
map it to another password with f<sub>1</sub>, which you then map with f<sub>2</sub> into yet another password, etc. until after applying f<sub>τ</sub> you get the
final password for the first row which I call z<sub>1</sub>. Then you put the pair (z<sub>1</sub>, pw<sub>1</sub>) into a hash map (you don't need to store
all elements of the rainbow table, for each row it suffices to represent the first and last only so a hash map is a good fit).
Then you proceed with the second row and do exactly the same as for the first. Before putting (z<sub>2</sub>, pw<sub>2</sub>) into your hash map,
you need to check if there's already an element with the same key value as z<sub>2</sub>  there. If not, all is well and you just proceed
to store (z<sub>2</sub>, pw<sub>2</sub>) in the hash map. if there's already a key with the same value as z<sub>2</sub>, you generate another value for pw<sub>2</sub> and try
deriving all passwords from the second row again. Repeat until you get to (z<sub>2</sub>, pw<sub>2</sub>) where z<sub>2</sub> is not present in the hash map.
Do the same for the remaining rows. At the end your hash map will contain l (z<sub>i</sub>, pw<sub>i</sub>) pairs where
each z<sub>i</sub> is unique. Actually, if you give it some thought, you will notice that the above also ensures that
all pw<sub>i</sub>'s are also unique. The below picture illustrates the process:

```
pw1 * f1 -> * f2 -> * f3 -> ... fτ * z1
pw2 * f1 -> * f2 -> * f3 -> ... fτ * z2
...
pwl * f1 -> * f2 -> * f3 -> ... fτ * zl
```

The total space required to store the hash map for the rainbow table to recover 8 character ascii passwords from
their SHA-256 hashes is just a few hundred GiB. Contrast this with a few PiB of storage one would need if they tried
to build a table for mapping all 8 character passwords to their SHA-256 hashes.

With you hash map for the rainbow table constructed, you are now ready to intercept password hashes and quickly recover
their passwords. The algorithm to do it is fairly simple. _Therein `L_hash_map` refers to the hash map that was introduced above,
y<sub>i</sub>(h) is denoted as y(i, h), likewise f<sub>i</sub>(z) is designated as f(i, z)_:
```
recover_password(h):
  z := y(τ, h)
  for i from τ-1 to 1:
    pw := L_hash_map[z]
    if pw != None:
      for j from 1 to i:
        pw := f(j, pw)
        if hash(pw) == y:
           return  pw 
    else:
      z = g(i, h);
      for j from i+1 to τ:
        z = f(j, z);
  return None
```

Assuming a system that uses 5 character long ascii passwords, given the following three MD4 hashes:
```
C89F2A956A8C8AE1F3D2B547BDA4498F
27300880ECECAAF7FF6705F10C6BC35F
8D850E3B2E28233C24432FCF45372B74
```
build a rainbow table and recover the original passwords. The base64 encodings of the original passwords are as follows (no peeking please):
```
clx4IDw=
KTlpMGg=
Il44LC4=
```

Keep in mind that the probability of the rainbow table containing the password you are looking for is around 63% so you
might need to build a couple of different rainbow tables to recover all the three passwords.

How do you protect your system from being vulnerable to such attacks? By ensuring that for each password there's also
a unique _salt_ value created from a large enough space. The identification system will then use a table with an additional column
to authenticate  the user logging in:
                                                         
 | user-id | Salt | Hash |
 |---------|------|------|
 | id<sub>1</sub>| salt<sub>1</sub> | H(salt<sub>1</sub> &#124;&#124; password<sub>1</sub>) |
 | id<sub>2</sub>| salt<sub>2</sub> | H(salt<sub>2</sub> &#124;&#124; password<sub>2</sub>) |
 | ...|...|...|
 | id<sub>n</sub>| salt<sub>n</sub> | H(salt<sub>n</sub> &#124;&#124; password<sub>n</sub>) |
