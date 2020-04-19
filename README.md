# cryptopals
Solutions to https://cryptopals.com problems

The only dependency on top of standard JRE 8 runtime is that on [Lombok](https://projectlombok.org).

## How to run
The majority of the challenges of a set can be run by executing the `com.cryptopals.Setx.main` method of the set.
Required dependencies are defined in the project's `pom.xml`.

Some challenges ([31](https://cryptopals.com/sets/4/challenges/31), 
[32](https://cryptopals.com/sets/4/challenges/32), [34](https://cryptopals.com/sets/5/challenges/34),
[35](https://cryptopals.com/sets/5/challenges/35), [36](https://cryptopals.com/sets/5/challenges/36),
[37](https://cryptopals.com/sets/5/challenges/37), [49](https://cryptopals.com/sets/7/challenges/49),
[57](https://toadstyle.org/cryptopals/57.txt), [58](https://toadstyle.org/cryptopals/58.txt),
[59](https://toadstyle.org/cryptopals/59.txt), [60](https://toadstyle.org/cryptopals/60.txt)) require a server-side application.
This can be produced with `mvn install` and executed with
```
java -jar cryptopals_server-0.2.0.jar
```
as a typical SpringBoot application. This application provides either a RESTful API or an RMI component depending on
a challenge.

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
```
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
on the offered subgroup description (p, q, g):
* Are both p and q prime?
* Does q divide p-1?
* Is g different from 1?
* Is g<sup>q</sup> equal 1?

The challenge does make two big assumptions though, namely that
* Bob will naively hang on to the same private key across all new sessions with Alice.
* That group Z<sub>p</sub><sup>*</sup> contains a large number of subgroups with small order. The attack will for example
not work if p is [a safe prime](https://en.wikipedia.org/wiki/Safe_prime).

### Challenge 58
[Challenge 58](https://toadstyle.org/cryptopals/58.txt) makes the attack from the previous challenge yet more realistic.
It can be mounted against a group where `p-1` has at least one large factor in addition to `q`.

The attack makes use of J.M. Pollard's Lambda Method for Catching Kangaroos, as outlined in
[Section 3 of Pollard's paper](https://www.ams.org/journals/mcom/1978-32-143/S0025-5718-1978-0491431-9/S0025-5718-1978-0491431-9.pdf).

Pollard's method employs a pseudo-random mapping function f that maps from set {1, 2, ..., p-1} to set {0, 1, ... k-1}.
The challenge suggested the following simplistic definition for f (which is similar to what Pollard gives in one of his examples):
```
f(y) = 2^(y mod k)
```
I used ceil(log<sub>2</sub>&radic;b + log<sub>2</sub>log<sub>2</sub>&radic;b - 2) for calculating `k`, which is based on
the suggestion in Section 3.1 of [this paper by Ravi Montenegro and Prasad Tetali](https://arxiv.org/pdf/0812.0789.pdf). 

When deciding on the amount of jumps N that the tame kangaroo is to make, I used the suggestion from the challenge
description and set N to the mean of range of f multiplied by 4. With this choice of the constant the probability of
Pollard's method finding the dlog is 98%.

I generate group Z<sub>p</sub><sup>*</sup> as follows:
* `p` is a 1024-bit prime meeting the following  requirement: `p = Nq + 1`, where `q` is a 42-bit prime. This
is based on the advice from Section 11.6 of "Cryptography Engineering, 2<sup>nd</sup> edition" by Niels Ferguson,
Bruce Schneier, and Tadayoshi Kohno.
* The generator `g` is a random member of Z<sub>p</sub><sup>*</sup> that has an order of `q`.

The only deviation from the book is that I use fewer than 256 bits for `q`, which obviously weakens the group. Unfortunately
Pollard's kangaroo algorithm doesn't lend itself to parallelisation so choosing `q` to be much larger than 42 bits makes the
attack impracticle. E.g. with a 42-bit q the attack takes on the order of 20 minutes on my MacBook Pro.

To make the attack more realistic I establish only one session to Bob to find `b mod r`, where `r` is one factor of `N`.
This no longer assumes that Bob uses the same private key across all new sessions with Alice. The attack thus works
in a realistic setting where Bob generates a new private key for each new session.

**NB:** The attack will still be infeasible if `p` is chosen to be a safe prime. However such choices of Z<sub>p</sub><sup>*</sup>
are rare as they lead to more computationally intensive exponentiation in the group.


### Challenge 59
[Challenge 59](https://toadstyle.org/cryptopals/59.txt) is based on the Weierstrass form of representing
elliptic curves: y<sup>2</sup> = x<sup>3</sup> + ax + b

When implementing the group operation in E(F<sub>p</sub>), division should be carried out as multiplication by
the multiplicative inverse mod p, e.g.:
```
function combine(P1, P2):
    if P1 = O:
        return P2

    if P2 = O:
        return P1

    if P1 = invert(P2):
        return O

    x1, y1 := P1
    x2, y2 := P2

    if P1 = P2:
        m := ( (3*x1^2 + a) * modInv(2*y1, p) ) mod p
    else:
        m := ( (y2 - y1) * modInv(x2 - x1, p) ) mod p

    x3 := ( m^2 - x1 - x2 ) mod p
    y3 := ( m*(x1 - x3) - y1 ) mod p

    return (x3, y3)
```

For convenience's sake I implemented the class that represents elements of the curve so that each coordinate 
of a point (x, y) is positive, i.e. `x` and `y` are stored `mod p`. This makes the implementation simpler.

For the rest the attack is pretty similar to [Challenge 57](https://toadstyle.org/cryptopals/57.txt) except
that the group given in the challenge
```
ECGroup(modulus=233970423115425145524320034830162017933, a=-95051, b=11279326, order=233970423115425145498902418297807005944)
```
doesn't have an order with many small factors. Therefore instead of finding generators of the small subgroups of this 
elliptic curve group, the attack hinges on Alice foisting on Bob bogus public keys that are not on the original
elliptic curve but are rather on specially crafted curves
```
ECGroup(modulus=233970423115425145524320034830162017933, a=-95051, b=210, order=233970423115425145550826547352470124412)
ECGroup(modulus=233970423115425145524320034830162017933, a=-95051, b=504, order=233970423115425145544350131142039591210)
ECGroup(modulus=233970423115425145524320034830162017933, a=-95051, b=727, order=233970423115425145545378039958152057148)
```

The orders of these elliptic curves do have many small factors. Interestingly all the three crafted curves are required
to recover Bob's private key. This is because the product of the small factors of each of these curves is less than
the order of the generator given for the challenge `(182, 85518893674295321206118380980485522083)`. You need the distinct
small factors collected from all the crafted curves.

**NB** the algorithm suggested in Challenge 57 and this one for finding subgroups of required order
> Suppose the
  group has order q. Pick some random point and multiply by q/r. If you
  land on the identity, start over.

only works for _cyclic_ groups. For Challenge 57 it didn't matter much because Z<sub>p</sub><sup>*</sup> is always
cyclic. This doesn't hold for elliptic curve groups though, i.e. not every elliptic curve group is cyclic. In fact you
will not be able to find a generator of order 2 for `y^2 = x^3 - 95051*x + 210` if you use the order of the group
233970423115425145550826547352470124412. The correct way to find generators of required order is to use the order
of the largest cyclic subgroup of an elliptic curve. For this curve it is 116985211557712572775413273676235062206.
See [my discussion with @spdevlin](https://twitter.com/_ilchen_/status/1174045790748254210?s=20).

The attack in this challenge does make two assumptions though, namely that
* Bob will hang on to the same private key across all new sessions with Alice. This is the same as in Challenge 57.
* Bob will not check whether Alice's public key lies on the expected elliptic curve. How big of an assumption
 is that? Unfortunately not too big because in many implementations of ECDH Bob is only sent the x coordinate of
 Alice's public key for the sake of efficiency, and the implementation doesn't check if x<sup>3</sup> + ax + b is
 a quadratic residue. In fact such an attack can be pulled off on the ubiquitous NIST P256 curve. It takes
 a twist-secure elliptic curve such as 25519 to foil this attack. Or one can just check if Alice's public key
 is on the expected curve, e.g. the following check by Bob will render this attack harmless:
```java
public Set8.Challenge59ECDHBobResponse initiate(ECGroup.ECGroupElement g, BigInteger q, ECGroup.ECGroupElement A) throws RemoteException {

    // A bit contrived for Bob to hang on to the same private key across new sessions, however this is what
    // Challenge 59 calls for.
    if (ecg == null  ||  !ecg.equals(g.group())  ||  !this.g.equals(g)) {
        ecg = g.group();
        this.g = g;
        privateKey = new DiffieHellmanHelper(ecg.getModulus(), q).generateExp().mod(q);
    }
    // Is Alice's public key on the curve?
    if (!ecg.containsPoint(A)) {
        throw  new RemoteException("Public key presented not on the expected curve");
    }
```

### Challenge 60
[Challenge 60](https://toadstyle.org/cryptopals/60.txt) is based on the Montgomery form of representing
elliptic curves: Bv<sup>2</sup> = u<sup>3</sup> + Au<sup>2</sup> + u

A Montgomery form curve equation can always be changed into the Weierstrass form, the converse is not always true.
Given isomorphism between EC groups of the same order regardless of their form, I abstracted the concept of
an EC point into an interface and refactored the rest of the classes accordingly. This ensured [a shared implementation
of the `scale` and `dlog` methods](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/ECGroupElement.java#L15-L91):
```java
public interface ECGroupElement {
    BigInteger  getX();
    BigInteger  getY();
    ECGroupElement  getIdentity();
    ECGroupElement  inverse();
    ECGroupElement  combine(ECGroupElement that);
    ECGroup  group();
    
    /** Returns the x coordinate of kP where P is this point */
        BigInteger  ladder(BigInteger k);

    default ECGroupElement  scale(BigInteger k) {
        ECGroupElement res = getIdentity(),  x = this;
        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (Set5.isOdd(k))  res = res.combine(x);
            x = x.combine(x);
            k = k.shiftRight(1);
        }
        return  res;
    }
}
```
Analogously for [the concept of an EC group](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/ECGroup.java#L14-L84):
```java
public interface ECGroup {

    /** Returns the order of field F<sub>p</sub> */
    BigInteger  getModulus();

    /** Returns the order of this curve, i.e. the number of points on it. */
    BigInteger  getOrder();

    /** If this group is cyclic, returns its order. Otherwise returns the order of the largest cyclic subgroup. */
    BigInteger  getCyclicOrder();

    /** Returns the identity element of this group */
    ECGroupElement  getIdentity();

    /**
     * Returns the order of the quadratic twist of this curve
     */
    default BigInteger  getTwistOrder() {
        return  getModulus().multiply(TWO).add(TWO).subtract(getOrder());
    }

    /**
     * Calculates the y coordinate of a point on this curve using its x coordinate
     */
    BigInteger  mapToY(BigInteger x);

    /** Checks if the point {@code elem} is on this curve */
    boolean  containsPoint(ECGroupElement elem);

    /** Creates a point on this curve with designated coordinates */
    ECGroupElement createPoint(BigInteger x, BigInteger y);

    BigInteger  ladder(BigInteger x, BigInteger k);
}
```
**NB** For a Montgomery curve the point at infinity O is always (0, 1). Each Montgomery curve has at least one point of order 2,
it is always (0, 0).

This challenge turned out to be one of the toughest so far. Here Alice sends Bob only the x-coordinate of her public key.
Bob then derives the DH symmetric key using the Montgomery ladder: `group.ladder(xA, b)`, where xA is the
x-coordinate of Alice's public key and b is Bob's private key. Bob also sends back to Alice only the x-coordinate of
his public key: `g.ladder(privateKey)`, where g is the generator of the EC group.

What makes this challenge much more computationally intensive is that when the protocol uses only the x-coordinates
of Alice's public key, Alice never learns the exact residues of Bob's private key when she foists public keys that
are in fact generators of small subgroups. @spdevlin, the author of the challenge, gives a small hint:
> HINT: You may come to notice that k*u = -k*u, resulting in a
  combinatorial explosion of potential CRT outputs. Try sending extra
  queries to narrow the range of possibilities.
  
By way of illustration, based on an arbitrarily generated Bob's private key. The twist of the curve has small subgroups of
the following orders [11, 107, 197, 1621, 105143, 405373, 2323367]. Sending the generators of these subgroups disguised as Alice's public
keys, gives you the following facts about Bob's private key b:
```
Generator of order 11 found: 76600469441198017145391791613091732004
Found b mod 11: 4 or 11-4=7
Generator of order 107 found: 215154098129284057249603159073175023533
Found b mod 107: 24 or 107-24=83
Generator of order 197 found: 94955123407611383099634454718224635806
Found b mod 197: 44 or 197-44=153
Generator of order 1621 found: 90340124320150600231802526508276130439
Found b mod 1621: 390 or 1621-390=1231
Generator of order 105143 found: 226695433509445480278297098756629724558
Found b mod 105143: 6979 or 105143-6979=98164
...
```
You thus have 2<sup>7</sup>=128 combinations of Bob's private key modulo the product of the
[11, 107, 197, 1621, 105143, 405373, 2323367] moduli. And then you'll need to take a DLog for each of these combinations
to end up with 128 guesses of Bob's private key. This will probably take a few days to compute on a typical laptop. 
Can we do better? Yes, it is possible to ensure that the amount of combinations grows not exponentially but linearly
in the number of subgroups. The solution I came up with works as follows. After finding the next pair of possible
b mod r<sub>n</sub> = k<sub>n</sub> or r<sub>n</sub>-k<sub>n</sub> combinations, find a generator of order
comp=r<sub>n-1</sub>*r<sub>n</sub> and discover two possibilities for b mod comp = kk or comp-kk.

Then using Garner's formula with

garnersFormula(k<sub>n-1</sub>, r<sub>n-1</sub>, k<sub>n</sub>, r<sub>n</sub>)<br>
garnersFormula(k<sub>n-1</sub>, r<sub>n-1</sub>, r<sub>n</sub>-k<sub>n</sub>, r<sub>n</sub>)<br>
garnersFormula(r<sub>n-1</sub>-k<sub>n-1</sub>, r<sub>n-1</sub>, k<sub>n</sub>, r<sub>n</sub>)<br>
garnersFormula(r<sub>n-1</sub>-k<sub>n-1</sub>, r<sub>n-1</sub>, r<sub>n</sub>-k<sub>n</sub>, r<sub>n</sub>)

you narrow the four combinations to just two that match kk or comp-kk. Implementation details are a bit more messy
than this explanation. I ended up creating [a class dedicated to tracking different allowed combinations of residues](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/CRTCombinations.java)
moduli [11, 107, 197, 1621, 105143, 405373, 2323367]. The class implements
[Iterable<BigInteger[][]>](https://docs.oracle.com/javase/8/docs/api/java/lang/Iterable.html) and thus allows iterating
through all legit combinations of possible residues to try. Another complication is that finding b mod comp requires
ploughing through large ranges for the bigger subgroups. For example to find b mod (1621*105143) requires wading through
the [0, 1621*105143/2] range, and for each element of the range you need to calculate a DH key and derive a MAC.
Without parallelizing this easily takes an hour. I therefore implemented [logic to carry such scans in parallel](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/Set8.java#L271-L317).

This challenge is an excellent demonstration of the extra safety that one obtains by using only the x-coordinates
of Alice's and Bob's public keys when implementing DH on an elliptic curve group. If Alice and Bob go a step further
and also ensure that they use a twist secure elliptic curve group E(GF(p)) such as
[the curve 25519](https://en.wikipedia.org/wiki/Curve25519), their implementation will be almost bullet-proof. E.g.
a twist secure elliptic curve group is one whose quadratic twist Ē(GF(p)) has a prime order or an order without any
small subgroups.


### Challenge 61
The first part of [Challenge 61](https://toadstyle.org/cryptopals/61.txt) that concerns itself with Duplicate Signature
Key Selection (DSKS) for ECDSA is almost trivial compared to anything else in Sets 7 and 8.
[The implementation is quite compact](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/ECDSA.java#L15-L63)
and simpler than DSA atop of Zp* since there's only group E(F<sub>p</sub>) to deal with rather than two groups
Z<sub>p</sub><sup>\*</sup> and Z<sub>q</sub><sup>\*</sup> as is the case in the
classical DSA. [The effort to produce a DSKS for ECDSA is negligible](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/Set8.java#L468-L482),
even for an industry standard curve such as [the curve 25519](https://en.wikipedia.org/wiki/Curve25519):
```java
@Test
void challenge61ECDSA() {
    MontgomeryECGroup   curve25519 = new MontgomeryECGroup(CURVE_25519_PRIME,
            valueOf(486662), ONE, CURVE_25519_ORDER.shiftRight(3), CURVE_25519_ORDER);
    MontgomeryECGroup.ECGroupElement   curve25519Base = curve25519.createPoint(
            valueOf(9), curve25519.mapToY(valueOf(9)));
    BigInteger   q = curve25519.getCyclicOrder();
    ECDSA   ecdsa = new ECDSA(curve25519Base, q);
    DSAHelper.Signature   signature = ecdsa.sign(CHALLENGE56_MSG.getBytes());
    ECDSA.PublicKey   legitPk = ecdsa.getPublicKey(),
            forgedPk = Set8.breakChallenge61ECDSA(CHALLENGE56_MSG.getBytes(), signature, ecdsa.getPublicKey());
    assertTrue(legitPk.verifySignature(CHALLENGE56_MSG.getBytes(), signature));
    assertTrue(forgedPk.verifySignature(CHALLENGE56_MSG.getBytes(), signature));
    assertNotEquals(legitPk, forgedPk);
}
```

Mounting a DSKS attack on RSA is much more laborious. I implemented it for relatively small RSA moduli of 320 bits.
The biggest effort went into finding primes `p` and `q` that meet the requirements for 1) `p-1` and `q-1` being smooth, 2)
both `s` and `pad(m)` (`s^e = pad(m) mod N`) being generators of the entire Zp* and Zq* groups, and 3) `gcd(p-1, q-1)=2`.
I used PKCS#1 v1.5 mode 1 padding with SHA-1, just like in [Challenge 42](https://cryptopals.com/sets/6/challenges/42).
Since the overhead of PKCS#1 padding with SHA-1 is at least 20+3+15+1=39 bytes, the minimum RSA modulus is 316 bits.

I ended up writing [quite a bit of concurrent code](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/Set8.java#L532-L598)
to tackle this, and pre-calculated all small primes less than 2<sup>20</sup>
so as to be able to find primes meeting the criterion 1) above in linear time. Even with such relatively small moduli
(both p and q are around 160 bits), finding them takes on the order of 20 minutes on my MacBook Pro with all cores searching.
**NB** it is vital that p*q is larger than the modulus of the original public key, so I search for primes that are 161 bits
long to play it safe.
```
Suitable primes found:
DiffieHellmanUtils.PrimeAndFactors(p=2252226720431925817465020447075111488063403846689, factors=[2, 7, 277, 647, 2039, 2953, 14633, 139123, 479387, 904847]),
DiffieHellmanUtils.PrimeAndFactors(p=2713856776699319359494147955700110393372009838087, factors=[2, 13, 17, 23, 26141, 56633, 80429, 241567, 652429, 1049941])]
```

After that I calculate ep=log<sub>s</sub>(pad(m)) mod p and eq=log<sub>s</sub>(pad(m)) mod q using [a combination of
Pohlig-Hellman and J.M. Pollard's Lambda Method](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/Set8.java#L485-L530) using a technique from [Challenge 59](https://toadstyle.org/cryptopals/58.txt).
To make Pollard's Lambda Method tractable I ensured that the product
of all prime factors for each of `p-1` and `q-1` is at least 3700000000000000000000000000000000. I arrived at this 
number heuristically, for DLogs whose prime is around 160 bits long Pollard's Lambda Method works reasonably fast.

The following part of the problem description deserves a word of caution
> 4\. Use the Chinese Remainder Theorem to put ep and eq together:

         e' = crt([ep, eq], [p-1, q-1])
The reasoning behind this formula is pretty straightforward: we know that s<sup>ep</sup>&equiv;pad(m) mod p and that
s<sup>eq</sup>&equiv;pad(m) mod q. Since the computations are in GF(p) and GF(q) by Fermat's theorem this is equivallent to
s<sup>ep mod (p-1)</sup>&equiv;pad(m) mod p and s<sup>eq mod (q-1)</sup>&equiv;pad(m) mod q. Thus we need to find e such that 
e &equiv; ep mod (p-1) and e &equiv; eq mod (q-1). However plugging it into the CRT formula

> e = ( ((ep−eq) ((q-1)<sup>−1</sup> mod (p-1) )) mod (p-1) )·(q-1) + eq

will fail because (q-1) is not invertible mod (p-1) as they are both even. I used the approach delineated
in Section 4.1 of [this paper](http://mpqs.free.fr/corr98-42.pdf) to correctly tackle it.

Thwarting DSKS attacks is trivial, the signer needs to attach their public key to the message before signing it. While 
the verifier should do an extra check to ensure the public key they use to verify corresponds to the one added
to the message. This way, the signing public key is authenticated along with the message. On top of it it makes sense
to pay attention to the public keys of RSA and be suspicious of public exponents `e` that are not among the commonly
used ones: { 3, 5, 17, 65537 }.


### Challenge 63
[Challenge 63](https://toadstyle.org/cryptopals/63.txt) consists of six parts:
1. Implementing GF(2<sup>128</sup>) &mdash; Polynomial Galois field over GF(2)
2. Implementing Galois Counter Mode (GCM) where the earlier devised GF(2<sup>128</sup>) is used to calculate 
the one-time-MAC &mdash; GMAC
3. Implementing a polynomial ring over GF(2<sup>128</sup>)
4. Solving the problem of factoring polynomials
5. Realising the actual attack of recovering the authentication key of GMAC provided a nonce was repeated
6. Asking yourself a question of what you can do with the recovered authentication key

All in all it is a fairly laborious challenge that took me quite some time to complete. The effort is commensurate
to a university coursework. On the other hand it helped me consolidate my understanding of finite fields
and polynomial rings like no text book would ever permit.

#### Implementing GF(2<sup>128</sup>)
I came up with a fairly straightforward implementation of GF(2<sup>128</sup>) using [Java's BigInteger](https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html).
See [com.cryptopals.set_8.PolynomialGaloisFieldOverGF2](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialGaloisFieldOverGF2.java)
for details.

#### Implementing Galois Counter Mode (GCM)
A correct implementation of GCM turned out a bit more tricky to get right. Here are a couple of important nuances to
bear in mind:
* When preparing a buffer over which to calculate the GMAC `a0 || a1 || c0 || c1 || c2 || len(AD) || len(C)` everything
must be encoded using a big-endian ordering. Padding is done with zero bits appended.
I found [this document from NIST](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) to
to be a good reference.
* When converting blocks of plain text into elements of GF(2<sup>128</sup>) and vice versa, the following enjoinder
from @spdevlin is crucial
> We can convert a block into a field element trivially; the leftmost bit is the coefficient of x^0, and so on.

At the end all fell into place and I was able to confirm my implementation of the GCM to produce the same results
as that from the JRE:
```java
@Test
void GCM() {
    KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
    SecretKey key = aesKeyGen.generateKey();
    GCM   gcm = new GCM(key);
    byte[]   nonce = new byte[12],  plnText = CHALLENGE56_MSG.getBytes(),  cTxt1,  cTxt2,  assocData = new byte[0];
    new SecureRandom().nextBytes(nonce);
    cTxt1 = gcm.cipher(plnText, assocData, nonce);

    // Confirm that we get the same ciphertext as that obtained from a reference implementation.
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    // Create GCMParameterSpec
    GCMParameterSpec   gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
    cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
    cTxt2 = cipher.doFinal(plnText);
    assertArrayEquals(cTxt2, cTxt1);

    // Confirm that decrypting will produce the original plain text
    assertArrayEquals(plnText, gcm.decipher(cTxt1, assocData, nonce));

    // Confirm that garbling a single byte of cipher text will result in the bottom symbol
    cTxt1[0] ^= 0x03;
    assertArrayEquals(null, gcm.decipher(cTxt1, assocData, nonce));
}
```

#### Implementing a polynomial ring over a finite field
Instead of implementing a polynomial ring over GF(2<sup>128</sup>) I decided to implement it as
[a generic class](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialRing2.java)
over [any finite field](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/FiniteFieldElement.java):
```java
public interface FiniteFieldElement {
    FiniteFieldElement  add(FiniteFieldElement e);
    FiniteFieldElement  subtract(FiniteFieldElement e);
    /**
     * Computes this + this + ... + this {@code k} times
     * @return  an object of the implementing class.
     */
    FiniteFieldElement  times(BigInteger k);
    FiniteFieldElement  multiply(FiniteFieldElement e);
    FiniteFieldElement  modInverse();
    /**
     * Computes this * this * ... * this {@code k} times, i.e. computes this<sup>k</sup>
     * @return  an object of the implementing class.
     */
    FiniteFieldElement  scale(BigInteger k);
    FiniteFieldElement  getAdditiveIdentity();
    FiniteFieldElement  getMultiplicativeIdentity();
    BigInteger  getOrder();
    BigInteger  getCharacteristic();
}
```

So as to test my implementation of polynomial rings, I wrote a class representing
[GF(Z<sub>p</sub>) fields](https://github.com/ilchen/cryptopals/blob/master/src/test/java/com/cryptopals/ZpField.java).
It is much easier to reason about Z<sub>p</sub> arithmetic than arithmetic in GF(2<sup>128</sup>).

#### Solving the problem of factoring polynomials
This entailed working out:
* Division of polynomials: https://en.wikipedia.org/wiki/Polynomial_long_division#Pseudocode
* Differentiation of polynomials
* GCD for polynomials
* Square-free factorization of polynomials: https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Square-free_factorization
* Distinct-degree factorization of polynomials: https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization
* Equal-degree factorization of polynomials: https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Equal-degree_factorization

##### Distinct-degree factorization
Of these problems I spent the most time getting distinct-degree factorization to work. The first obstacle I faced was my earlier
decision to represent polynomials as [arrays of coefficients](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialRing.java#L14-L22).
This algorithm requires dealing with polynomials whose degree is the order of the field and higher, which turns out
to be 2<sup>128</sup> for this field. E.g. a polynomial like this one:
x<sup>2<sup>128</sup></sup> - x = x<sup>340282366920938463463374607431768211456</sup> + x in GF(2<sup>128</sup>).
To tackle it I switched to representing polynomials in [a way that stores only their non-zero coefficients](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialRing2.java#L13-L25).

The second obstacle was the awful running time of [the Distinct-degree factorization algorithm from Wikipedia](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization).
It has a running time of O(q) where q is the order of GF(2<sup>128</sup>), which takes forever. I tackled it by
adopting [a Distinct-degree factorization algorithm that uses repeated squaring](https://www.cmi.ac.in/~ramprasad/lecturenotes/comp_numb_theory/lecture10.pdf).

##### Equal-degree factorization
Equal-degree factorization, while fairly well delineated by @spdevlin, presented a couple of difficulties too. To start
with, calculating
```g := h^((q^d - 1)/3) - 1 mod f```
as specified in the problem description will take forever for the very same reason as I indicated above &mdash;
the order (q<sup>d</sup>-1)/3 will be too large. You need to raise to this high a power by constantly taking modulus
of f in your exponentiation routine. I solved it by implementing [a scaleMod method](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialRing2.java#L235-L257) on my Polynomial Ring class.

The other difficulty is that the square-free polynomial without distinct-degree factors that you pass to your edf implementation 
might not have factors of the degree you specify. This would lead to the algorithm running ad infinitum...
For example in my approach I always call edf with a desired degree of factors being 1. While the setting guarantees
the presence of at least one factor of degree 1 for the original polynomial, there's no guarantee that each polynomial
spewed out by distinct-degree factorization can be factoed in one-degee polynomials. I dealt with this predicament
by setting a heuristic limit on the maximum number of passes through the loop in my edf implementation. When the polynomial
passed to edf  has factors of requested degree, this heuristic limit will not halt the loop without finding the factors
with a probability close to 1.
```java
// maxPasses ensures the method doesn't hang if this polynomial can't be factored into d-degree polynomials
int   maxPasses = 5 * (int) Math.ceil((32 - Integer.numberOfLeadingZeros(r)) * 2.5);
```

#### Realising the actual attack of recovering the authentication key
All the hard work on implementing square-free factorization, distinct-degree factorization, end equal-degree factorization
can finally be brought to bear:
```java
KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
SecretKey key = aesKeyGen.generateKey();
GCM   gcm = new GCM(key);
byte[]   nonce = new byte[12],  plnText = "crazy flamboyant for the rap enjoyment".getBytes(),
                               plnText2 = "dummy text to try".getBytes(),
         cTxt1,  cTxt2,  assocData = "valid assoc.Data".getBytes();
new SecureRandom().nextBytes(nonce);
// a0 || a1 || c0 || c1 || c2 || (len(AD) || len(C)) || t
cTxt1 = gcm.cipher(plnText, assocData, nonce);
// Reusing the same nonce, thereby making ourselves vulnerable to the attack.
cTxt2 = gcm.cipher(plnText2, assocData, nonce);


PolynomialRing2<PolynomialGaloisFieldOverGF2.FieldElement>   poly1 = GCM.toPolynomialRing2(cTxt1, assocData),
                                                             poly2 = GCM.toPolynomialRing2(cTxt2, assocData),
                                                             equation = poly1.add(poly2).toMonicPolynomial();
System.out.println("cTxt1 polynomial: " + poly1);
System.out.println("cTxt2 polynomial: " + poly2);
System.out.println("Equation: " + equation);

List<PolynomialRing2<PolynomialGaloisFieldOverGF2.FieldElement>>
        allFactors = equation.squareFreeFactorization().stream().map(PolynomialRing2.PolynomialAndPower::getFactor)
                .flatMap(x -> x.distinctDegreeFactorization().stream()).collect(Collectors.toList()),

        oneDegreeFactors = allFactors.stream().filter(x -> x.intDegree() == 1).collect(Collectors.toList()),

        oneDegreeFactorsThroughEdf = allFactors.stream().filter(x -> x.intDegree() > 1)
            .flatMap(x -> x.equalDegreeFactorization(1).stream()).collect(Collectors.toList());

System.out.println("Actual authentication key: " + gcm.getAuthenticationKey());
System.out.println("Candidates found after distinct-degree factorization: " + oneDegreeFactors);
System.out.println("Additional candidates found after equal-degree factorization: " + oneDegreeFactorsThroughEdf);

oneDegreeFactors.addAll(oneDegreeFactorsThroughEdf);
List<PolynomialGaloisFieldOverGF2.FieldElement>   candidateAuthenticationKeys =
        oneDegreeFactors.stream().map(x -> x.getCoef(0)).collect(Collectors.toList());
assertTrue(candidateAuthenticationKeys.contains(gcm.getAuthenticationKey()));
```

Running it produces the following output:
```
cTxt1 polynomial: 862e862274c6f6cece8604269636866ex^5 + a2c92e99dba07ce117b3bb3665fedff9x^4 + f4551f6d035a339b2e5b061ca2830ce4x^3 + 320f10f267edx^2 + c800000000000000100000000000000x + 5aafa98bf7b25cfe22f5e630f97d59e9
cTxt2 polynomial: 862e862274c6f6cece8604269636866ex^4 + c291acf103e2e47987fbbb368dce3f19x^3 + 7ex^2 + 11000000000000000100000000000000x + b3180499d9b2e60566ac9c204aad7ff
Equation: x^5 + 597419e85ea532a59c4d0eed034a9044x^4 + 812f7801991ead15d455a70fcb83086fx^3 + 87c24da8d5f25ea3e9f92b8c9b319712x^2 + 10ec19974d245b5f16890e6a1effeec8x + e4cb0203ef19430f3c13947f6f6d17a7
Actual authentication key: 67cf01239432c85151d9f7c021bfd121
Candidates found after square-free and distinct-degree factorization: []
Additional candidates found after equal-degree factorization: [x + 67cf01239432c85151d9f7c021bfd121, x + e8cde43205a09d05379422572e11dfb5]
```

#### Asking yourself a question of what you can do with the recovered authentication key
Having gone to the lengths of completing this Herculean labour of recovering the GMAC authentication key from a victim
who naively encrypted two different plain texts with the same nonce, you might wonder what you can do with it. Well,
you can forge a piece of distinct cipher text that the cryptosystem you attack will authenticate. In other words you can
mount an _existential forgery_ attack.

Imagine that `t0` is the last block of the first cipher text you have `cTxt1`. Looking at the way it was calculated

```t0 = a0*h^5 + c0*h^4 + c1*h^3 + c2*h^2 + l0*h + s```

and noting that you have both `a0` and `h`, you can go far. Say `a'0` is a block of your bogus associated data you want to swap for
the legitimate block `a0`. What you do is first subtract `a0*h^5` from `t0` and then replace it with a block of bogus
associated data by adding `a'0*h^5` to `t0`. Here's how it looks in my code:
```java
/**
 * Forges valid cipher text from legit cipher text and associated data coupled with a recovered authentication key.
 * @param additionalBogusAssocData  blocksize-long buffer, must be the same size as padded {@code legitAssocData}
 */
public static byte[]  forgeCipherText(byte[] legitCipherText, byte[] legitAssocData, byte[] additionalBogusAssocData,
                                      PolynomialGaloisFieldOverGF2.FieldElement authenticationKey) {
    int    plainTextLen = legitCipherText.length - BLOCK_SIZE,
           assocDataPaddedLen = (legitAssocData.length / BLOCK_SIZE + (legitAssocData.length % BLOCK_SIZE != 0  ?  1 : 0)) * BLOCK_SIZE,
           plainTextPaddedLen = (plainTextLen / BLOCK_SIZE + (plainTextLen % BLOCK_SIZE != 0  ?  1 : 0)) * BLOCK_SIZE,
           lastPower = plainTextPaddedLen / BLOCK_SIZE + 1,
           last = additionalBogusAssocData.length / BLOCK_SIZE;

    if (additionalBogusAssocData.length != assocDataPaddedLen) {
        throw new IllegalArgumentException("additionalBogusAssocData must be of same length as padded legit associated data and not "
                                           + additionalBogusAssocData.length);
    }

    // We start with the original legit tag...
    PolynomialGaloisFieldOverGF2.FieldElement   forgedTag = toFE(Arrays.copyOfRange(
            legitCipherText, legitCipherText.length - BLOCK_SIZE, legitCipherText.length));

    byte[]   buf = new byte[assocDataPaddedLen];
    System.arraycopy(legitAssocData, 0, buf, 0, legitAssocData.length);

    // ... and then subtract from it the legit associated data and
    //     add to it bogus associated data.
    for (int i=last; i > 0; i-=1) {
        lastPower++;

        // Remove the summand of the legit associated data
        forgedTag = forgedTag.subtract(
                toFE( Arrays.copyOfRange(legitAssocData, (last - 1) * BLOCK_SIZE, last * BLOCK_SIZE))
                        .multiply(authenticationKey.scale(valueOf(lastPower))) );

        // And then add the summand of the bogus associate data
        forgedTag = forgedTag.add(
                toFE( Arrays.copyOfRange(additionalBogusAssocData, (last - 1) * BLOCK_SIZE, last * BLOCK_SIZE))
                    .multiply(authenticationKey.scale(valueOf(lastPower))) );
    }
    byte[]  res = legitCipherText.clone();
    System.arraycopy(forgedTag.asArray(), 0, res, legitCipherText.length - BLOCK_SIZE, BLOCK_SIZE);
    return  res;
}
```

Giving it a spin:
```
cTxt1 polynomial: 862e862274c6f6cece8604269636866ex^5 + a2c92e99dba07ce117b3bb3665fedff9x^4 + f4551f6d035a339b2e5b061ca2830ce4x^3 + 320f10f267edx^2 + c800000000000000100000000000000x + 5aafa98bf7b25cfe22f5e630f97d59e9
cTxt2 polynomial: 862e862274c6f6cece8604269636866ex^4 + c291acf103e2e47987fbbb368dce3f19x^3 + 7ex^2 + 11000000000000000100000000000000x + b3180499d9b2e60566ac9c204aad7ff
Equation: x^5 + 597419e85ea532a59c4d0eed034a9044x^4 + 812f7801991ead15d455a70fcb83086fx^3 + 87c24da8d5f25ea3e9f92b8c9b319712x^2 + 10ec19974d245b5f16890e6a1effeec8x + e4cb0203ef19430f3c13947f6f6d17a7
Actual authentication key: 67cf01239432c85151d9f7c021bfd121
Candidates found after square-free and distinct-degree factorization: []
Additional candidates found after equal-degree factorization: [x + 67cf01239432c85151d9f7c021bfd121, x + e8cde43205a09d05379422572e11dfb5]

Recovered authentication key: 67cf01239432c85151d9f7c021bfd121
Legit associated data: valid assoc.Data
Bogus associated data: bogus assoc.Data
Legit  cipher text: 9FFB7FA66CDDCDE8873E05DB997493452730C1453860DA74D9CC5AC0B6F8AA2FB7E64F08F04C979ABE9F0C67AF447F3A4DEFD195F55A
Forged cipher text: 9FFB7FA66CDDCDE8873E05DB997493452730C1453860DA74D9CC5AC0B6F8AA2FB7E64F08F04CDE9E643787D35A6765241FEC4324627A
Decrypted by the crypto system under attack into: crazy flamboyant for the rap enjoyment

Recovered authentication key: e8cde43205a09d05379422572e11dfb5
Legit associated data: valid assoc.Data
Bogus associated data: bogus assoc.Data
Legit  cipher text: 9FFB7FA66CDDCDE8873E05DB997493452730C1453860DA74D9CC5AC0B6F8AA2FB7E64F08F04C979ABE9F0C67AF447F3A4DEFD195F55A
Forged cipher text: 9FFB7FA66CDDCDE8873E05DB997493452730C1453860DA74D9CC5AC0B6F8AA2FB7E64F08F04CD3355D1A58A0B6E730F4356A7027481F
Decrypted by the crypto system under attack into: ⊥
```
I am able to commit an existential forgery attack!

### Challenge 64
[Challenge 64](https://toadstyle.org/cryptopals/64.txt) implements an attack first outlined by Niels Ferguson in his 
[Authentication weaknesses in GCM](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf)
paper. GCM is the most popular standard for authenticated encryption and is used in TLS 1.2 and higher. Niels's paper
shows that the actual authentication security of GCM will be less than the number of bits in its tag because of 
peculiarities of the GHASH one-time hash function that GCM uses. Given the maximum legth tag size of 128 bits, the actual
authentication security of GCM is `n - k` bits where k is  &lfloor;log<sub>2</sub>(number-of-blocks-encrypted)&rfloor;.

Like Challenge 63, this challenge shows how to succeed at an existential forgery attack on GCM. This time without your
adversary having made any mistakes in using GCM apart for choosing a small tag size. 

To tackle this challenge you will need to implement the following parts.

1. Linear algebra routines for GF(2) and GF(2<sup>128</sup>):
   * Implementing a vector representation for elements of GF(2<sup>128</sup>);
   * Implementing a matrix representation for multiplication by a constant in GF(2<sup>128</sup>) and for squaring in GF(2<sup>128</sup>);
   * Implementing basic operations for matrices in GF(2): addition, multiplication, scaling, transposition,
   Gaussian elimination, finding a kernel. 
2. Extraction and replacement of 2<sup>i-th</sup> blocks of ciphertext counting from the end, i.e. all blocks of
   the ciphertext that are the coefficients of x<sup>2^i</sup> (where i = 1, 2, ..., n) in the GHASH polynomial
   in the indeterminate x over GF(2<sup>128</sup>).
3. Calculation of matrix A<sub>d</sub> = &sum;M<sub>Di</sub>(M<sub>S</sub>)<sup>i</sup>, where M<sub>Di</sub> are 
   matrix representations of the differences between the 2<sup>i-th</sup> element of ciphertext and its forged counterpart.
   Along with the calculation of the dependency matrix T, as explained in the challenge.
4. Finding the kernel of the matrix T, whose elements represent all the possible manipulations to the 2<sup>i-th</sup>
   blocks of ciphertext that don't change the most significant 16 bits of GHASH.
5. Attempting an existential forgery attack on the smallest allowed GHASH tag sice in GCM &mdash; 32 bits.
6. Recovering the authentication key.

#### Linear algebra
##### Implementing a vector representation for elements of GF(2<sup>128</sup>)
I added two new methods to my class for representing GF(2<sup>128</sup>) elements:
[PolynomialGaloisFieldOverGF2::FieldElement::asVector](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialGaloisFieldOverGF2.java#L150-L158)
and [PolynomialGaloisFieldOverGF2::createElement](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialGaloisFieldOverGF2.java#L47-L58)

##### Implementing a matrix representation for multiplication by a constant and for squaring
Analogously to vector representation, I wrote these as methods of my class for GF(2<sup>128</sup>):
[PolynomialGaloisFieldOverGF2::FieldElement::asMatrix](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialGaloisFieldOverGF2.java#L160-L173)
and [PolynomialGaloisFieldOverGF2::getSquaringMatrix](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/PolynomialGaloisFieldOverGF2.java#L64-L80)

##### Implementing basic operations for matrices in GF(2)
I felt it would be an overkill to create a whole new class to represent matrices in GF(2), instead I went for
a simple representation as `boolean[][]` and the [BooleanMatrixOperations class](https://github.com/ilchen/cryptopals/blob/master/src/main/java/com/cryptopals/set_8/BooleanMatrixOperations.java) with static methods whose methods
accept matrices and vectors in GF(2).

Time for some tests to validate that everything works correctly:
```java
@DisplayName("Linear algebra over GF(2)") @Test
void  linearAlgebraForChallenge64()  {
    BigInteger   modulus = ONE.shiftLeft(128).or(valueOf(135));
    PolynomialGaloisFieldOverGF2   gf = new PolynomialGaloisFieldOverGF2(modulus);
    PolynomialGaloisFieldOverGF2.FieldElement   c = gf.createElement(valueOf(3)),  y = gf.createElement(valueOf(15));

    assertEquals(c.multiply(y), gf.createElement(multiply(c.asMatrix(), y.asVector())) );
    assertEquals(y.multiply(y), gf.createElement(multiply(gf.getSquaringMatrix(), y.asVector())) );

    assertEquals(c, gf.createElement(multiply(c.asMatrix(), gf.getMultiplicativeIdentity().asVector())) );
    assertEquals(y, gf.createElement(y.asVector()));

    boolean[][][]   mss = new boolean[18][][];
    mss[0] = gf.getSquaringMatrix();
    for (int i=1; i < 18; i++) {
        mss[i] = multiply(mss[i-1], mss[0]);
    }
    assertEquals(y.scale(valueOf(2)), gf.createElement(multiply(mss[0],  y.asVector()) ));
    assertEquals(y.scale(valueOf(4)), gf.createElement(multiply(mss[1],  y.asVector()) ));
    assertEquals(y.scale(valueOf(8)), gf.createElement(multiply(mss[2],  y.asVector()) ));
    assertEquals(y.scale(valueOf(16)), gf.createElement(multiply(mss[3],  y.asVector()) ));

    // Mc * Ms^i * y) = c * y^4
    assertEquals(c.multiply(y.scale(valueOf(16))),
            gf.createElement(multiply(multiply(c.asMatrix(), mss[3]), y.asVector())) );

    // Confirm matrix representation of GHASH works correctly
    PolynomialGaloisFieldOverGF2.FieldElement    c1 = gf.createRandomElement(),  c2 = gf.createRandomElement(),
            c4 = gf.createRandomElement(),  c8 = gf.createRandomElement(),  h = gf.createRandomElement(),  tag1,  tag2;
    // t = c1*h + c2*h^2 + c4*h^4 + c8*h^8

    // First calculate the tag using plain GF(2^128)
    tag1 = c1.multiply(h).add(c2.multiply(h.scale(valueOf(2)))).add(c4.multiply(h.scale(valueOf(4)))).add(c8.multiply(h.scale(valueOf(8))));
    // Then do the same using a matrix-based representation of GF(2^128) operations
    tag2 = gf.createElement(multiply(add(add(add(c1.asMatrix(), multiply(c2.asMatrix(), mss[0])), multiply(c4.asMatrix(), mss[1])), multiply(c8.asMatrix(), mss[2])), h.asVector()));
    assertEquals(tag1, tag2);
}
```