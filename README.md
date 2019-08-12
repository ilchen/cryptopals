# cryptopals
Solutions to https://cryptopals.com problems

The only dependency on top of standard JRE 8 runtime is that on [Lombok](https://projectlombok.org).

## [Set 6](https://cryptopals.com/sets/6)
### Challenge 48
For [Challenge 48](https://cryptopals.com/sets/6/challenges/48) there's a dependency on https://github.com/square/jna-gmp/tree/master/jnagmp, which is a wrapper
around gmp 6.1.x. If you are on macOS, you probably already installed gmp when you installed python using brew. With
JRE's BigInteger Challenge 48 will take around 5 hours to finish. Using gmp it finishes under 1 hour.

## [Set 7](https://cryptopals.com/sets/7)
### Challenge 49
The second part of [this challenge](https://cryptopals.com/sets/7/challenges/49), which deals with a message length extension attack for a multiple transactions request:
> Your mission: capture a valid message from your target user. Use length extension to add a transaction paying the attacker's account 1M spacebucks.

assumes that the attacker and the victim share the same authentication key, which is quite a stretch.

### Challenge 52
[Challenge 52](https://cryptopals.com/sets/7/challenges/52) is one of the best demonstrations of the birthday paradox
I've seen. **NB:** the way this challenge defines the compression function containts
[a mistake](https://twitter.com/spdevlin/status/1134220310109024257). The correct definition should
be
```aidl
function MD(M, H, C):
  for M[i] in pad(M):
    H := C(M[i], H) ^ H
  return H
```

For the purposes of this task it makes sense to choose a cipher whose key size is 8 bytes. It will also be easier
if the cipher's key and block sizes are the same. I opted for Blowfish, which is present in all JREs through
`com.sun.crypto.provider.SunJCE provider`. I used a 16 bit hash for the easier hash function f, and a 32 bit hash for g.
This way I needed to find 2<sup>16</sup> messages colliding in f to ensure there's a pair among them colliding in g. 


### Challenge 55
[Challenge 55](https://cryptopals.com/sets/7/challenges/55) is probably one of the most interesting to work on.
I succeeded in implementing it in a uniform Object-Oriented way, which aids readability and maintainability.
The implementation is also blazingly fast -- it finds a collison within a few seconds. Here is one found with it:
```$xslt
Collision found between
	683E10B651E9185B4D9886D90B7634AE7C4D753533F75041C388E6ACF20CF8B12BA9C27368F09B22EDCE3445BBFED7E8636EDB70070DF0EB7449FA54E421D246
	683E10B651E918DB4D9886490B7634AE7C4D753533F75041C388E6ACF20CF8B12BA9C27368F09B22EDCE3445BBFED7E8636EDA70070DF0EB7449FA54E421D246
MD4: B9B0031B30D53E826B80CBDDBE7354D9
```
I succeeded in fully enforcing all constraints from the first round of MD4 as well as all constraints from the first two steps of the second round.
I didn't figure out how to apply the constraints from the 3rd step of the second round of MD4. X. Wang et al. give some
hints in their paper, yet they are not easy to follow
> Utilize more precise modification to correct some other conditions. For example, we can use the internal collision in Table 2 in which there are three message words are changed to correct c5,i, i = 26, 27, 29, 32. The precise modification should add some extra conditions in the first rounds (see Table 2) in advance. There are many other precise modifications.
c5,30 can be corrected by other modification. By various modifications, besides two conditions in the third round, almost all the conditions in rounds 1-2 will be corrected. The probability can be among 2^6 ∼ 2^2.

It is interesting to note that X. Wang et al. used differential cryptanalysis to discover the conditions that lead
to collisions in MD4. MD4 was developed in 1990 by Ron Rivest, which is also the year in which Eli Biham and Adi Shamir introduced
differential cryptanalysis. Obviously the designer of MD4 didn't take it into account while desigming MD4. Interestingly, the NSA
discovered differential cryptanalysis as early as in the 1970s, which is one of the reasons why DES is immune to it
(see [this paper](https://ieeexplore.ieee.org/abstract/document/5389567) or Section 12.4 in Bruce Schneier's Applied Cryptography
2<sup>nd</sup> edition for details).

### Challenge 56
[Challenge 56](https://cryptopals.com/sets/7/challenges/56) is an excellent demonstration of how even a tiny bias that
makes the distribution of a secure PRF slightly different from uniform might be enough to break it. In the case of RC4
bytes 2 to 255 of RC4 keystream have biases on the order of 1/2<sup>16</sup> or higher.

This challenge is based on the attack outlined in Section 4.1 of [this paper](http://www.isg.rhul.ac.uk/tls/RC4biases.pdf).
In my solution I used the biases in the 16<sup>th</sup> (Z<sub>16</sub>) and 32<sup>nd</sup> (Z<sub>32</sub>) bytes of RC4's keystream,
which are elucidated in Section 3.1 of the paper.

The essence of this attack is fairly simple -- the biases in the distributions of Z<sub>16</sub> and Z<sub>32</sub> make
the frequency of a few values much higher than 1/256 (`0x00`, `0xF0`, `0x10` for Z<sub>16</sub>;
and `0x00`, `0xE0`, `0x20` for Z<sub>32</sub>). If we ensure that we encrypt the same plaintext bytes in these positions
repeatedly, certain ciphertext values for C<sub>16</sub> and C<sub>32</sub> will also occur more frequently than others.
By encrypting on the order of 2<sup>24</sup> values, we construct the distribution of C<sub>16</sub> and C<sub>32</sub>,
which (like the distribution of Z<sub>16</sub> and Z<sub>32</sub>) will not be uniform. This is enough to recover the
original plaintext bytes P<sub>16</sub> and P<sub>32</sub> using the maximum-likelihood estimation.

Since the biases in Z<sub>16</sub> and Z<sub>32</sub>, while non-negligible, are still fairly small, I used 2<sup>27</sup>
RC4 keystreams (with independent 128-bit keys) to construct their frequency distributions. With smaller values such as 
2<sup>25</sup> or less, the recovered plaintext cookie will contain errors, particularly for P<sub>32</sub>. BTW: In the paper Nadhem J. AlFardan et al.
used 2<sup>44</sup> RC4 keystreams to determine the disributions of Z<sub>16</sub> and Z<sub>32</sub>. For this challenge
this would be an overkill.

For the maximum-likelihood estimation of the plaintext bytes I used 2<sup>24</sup> ciphertexts. This is enough to recover
P<sub>16</sub> and P<sub>32</sub> and fully corraborates the results in Figure 4 in the paper.

## [Set 8](https://toadstyle.org/cryptopals/)
### Challenge 57
[Challenge 57](https://toadstyle.org/cryptopals/57.txt) presented me with a need to
[implement Garner's algorithm](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/Set8.java#L44-L72) to
reconstruct Bob's private key from its residues per subset of the moduli of p-1.

All in all the challenge presents an attack that can bypass DH implementations where Bob makes some rudimentary checks
the offered subgroup description (p, q, g) for correctness:
* Are both p and q prime?
* Does q divide p-1?
* Is g different from 1?
* Is g<sup>q</sup> equal 1?

The challenge does make two big assumption though, namely that
* Bob will naively hang on to the same private key across all new sessions with Alice.
* That group Z<sub>p</sub><sup>*</sup> contains a large number of subgroups with small order. The attack will for example
not work if p is [a safe prime](https://en.wikipedia.org/wiki/Safe_prime).

### Challenge 58
[Challenge 58](https://toadstyle.org/cryptopals/58.txt) makes the attack from the previous challenge yet more realistic.
It can be mounted against a group where p-1 has one large factor,in which case it no longer requires that Bob use
the same private key across all new sessions with Alice. **NB:** The attack will still be infeasible if p is chosen
to be a safe prime.

The attack makes use of J.M. Pollard's Lambda Method for Catching Kangaroos, as outlined in
[Section 3 of Pollard's paper](https://www.ams.org/journals/mcom/1978-32-143/S0025-5718-1978-0491431-9/S0025-5718-1978-0491431-9.pdf).


Pollard's method makes use of a pseudo-random mapping function f that maps from set {1, 2, ..., p-1} to set {0, 1, ... k-1}.
The challenge suggested the following simplistic defintion for f (which is similar to what Pollard gives in one of his examples):
```aidl
f(y) = 2^(y mod k)
```
I used ceil(log<sub>2</sub>&radic;b + log<sub>2</sub>log<sub>2</sub>&radic;b - 2) for calculating k, which is based on
the suggestion in Section 3.1 of [this paper by Ravi Montenegro and Prasad Tetali](https://arxiv.org/pdf/0812.0789.pdf). 

When deciding on the amount of jumps N that the tame kangaroo is to make, I used the suggestion from the challenge
description and set N to the mean of range of f multiplied by 4. With this choice of the constant the probability of
Pollard's method finding the dlog is 98%.
