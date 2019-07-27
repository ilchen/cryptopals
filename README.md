# cryptopals
Solutions to https://cryptopals.com problems

The only dependency on top of standard JRE 8 runtime is that on Lombok https://projectlombok.org

## Challenge 48
For [Challenge 48](https://cryptopals.com/sets/6/challenges/48) there's a dependency on https://github.com/square/jna-gmp/tree/master/jnagmp, which is a wrapper
around gmp 6.1.x. If you are on macOS, you probably already installed gmp when you installed python using brew. With
JRE's BigInteger Challenge 48 will take around 5 hours to finish. Using gmp it finishes under 1 hour.

## Challenge 52
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


## Challenge 55
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

## Challenge 56
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
