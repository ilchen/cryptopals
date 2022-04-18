package com.cryptopals;

import com.cryptopals.set_5.DiffieHellmanHelper;
import com.cryptopals.set_5.RSAHelper;
import com.cryptopals.set_6.DSAHelper;
import com.cryptopals.set_6.RSAHelperExt;
import com.cryptopals.set_8.*;
import lombok.Data;
import lombok.SneakyThrows;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.cryptopals.set_6.DSAHelper.hashAsBigInteger;
import static java.math.BigInteger.*;

/**
 * Created by Andrei Ilchenko on 28-07-19.
 */
public class Set8 {
    public static final String   CHALLENGE56_MSG = "crazy flamboyant for the rap enjoyment";
    public static final String   MAC_ALGORITHM_NAME = "HmacSHA256";
    public static final BigInteger   NON_RESIDUE = valueOf(-1),  CHALLENGE60_COMPOSITE_MODULI_THREASHOLD = valueOf(100_000);
    static final BigInteger   P = new BigInteger(
            "7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475"
            + "480089726140708102474957429903531369589969318716771"),
                              G = new BigInteger(
             "45653563970957406554368545034838268321361061416395634877324381953436904376061178"
             + "28318042418238184896212352329118608100083187535033402010599512641674644143"),
                              Q = new BigInteger("236234353446506858198510045061214171961"),
            CURVE_25519_PRIME = ONE.shiftLeft(255).subtract(valueOf(19)),
            CURVE_25519_ORDER = ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493")).shiftLeft(3),
            CURVE_SECP256K1_PRIME = ONE.shiftLeft(256).subtract(ONE.shiftLeft(32)).subtract(valueOf(512)).subtract(valueOf(256))
                                                      .subtract(valueOf(128)).subtract(valueOf(64)).subtract(valueOf(16)).subtract(ONE),
            CURVE_SECP256K1_ORDER = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger   TWO = valueOf(2),  THREE = valueOf(3),  FOUR = valueOf(4),  FIVE = valueOf(5),
                                      EIGHT = valueOf(8);

    @Data
    public static class Challenge57DHBobResponse implements Serializable {
        final BigInteger B;
        final String   msg;
        final byte[]   mac;
    }

    @Data
    public static class Challenge59ECDHBobResponse implements Serializable {
        final ECGroupElement B;
        final String   msg;
        final byte[]   mac;
    }

    @Data
    public static class Challenge60ECDHBobResponse implements Serializable {
        final BigInteger xB;
        final String   msg;
        final byte[]   mac;
    }

    /**
     * An oracle for Challenge 64 that returns a GHASH error polynomial calculated over differences between the coefficients
     * of h<sup>2^i</sup> terms in legit and forged ciphertexts.
     * <br>
     * t = s + c<sub>1</sub>·h + c<sub>2</sub>·h<sup>2</sup> + c<sub>3</sub>·h<sup>3</sup> + ... + c<sub>n</sub>·h<sup>n</sup>
     */
    public interface  GcmFixedKeyAndNonceErrorPolynomialOracle {
        PolynomialGaloisFieldOverGF2.FieldElement  ghashPower2BlocksDifferences(
                PolynomialGaloisFieldOverGF2.FieldElement[] coeffs,
                PolynomialGaloisFieldOverGF2.FieldElement[] forgedCoeffs, PolynomialGaloisFieldOverGF2.FieldElement d0);
    }

    /**
     * Computes the Legendre symbol for the given parameter and prime
     * @return  0 if {@code p|a}, 1 if {@code a} is a quadratic residue modulo {@code p},
     *           -1 if {@code a} is a quadratic non-residue modulo {@code p}.
     */
    public static BigInteger  legendreSymbol(BigInteger a, BigInteger p) {
        return  a.modPow(p.subtract(ONE).shiftRight(1), p);
    }

    /**
     * Finds &radic;n mod p using <a href="https://en.wikipedia.org/wiki/Tonelli–Shanks_algorithm">the Tonelli–Shanks algorithm</a>.
     * Handles special cases of {@code p % 4 == 3}  and  {@code p % 8 == 5} with a more efficient approach. Returns
     * the principal square root in case {@code p % 4 == 3}.
     * @return  &radic;n mod p if n is a quadratic residue, {@link #NON_RESIDUE} otherwise
     */
    public static BigInteger  squareRoot(BigInteger n, BigInteger p) {
        BiFunction<BigInteger, BigInteger, BigInteger>   powModP = (BigInteger a, BigInteger e) -> a.modPow(e, p);
        if (!legendreSymbol(n, p).equals(ONE))  return  NON_RESIDUE;
        if (p.mod(FOUR).equals(THREE))  return  n.modPow(p.add(ONE).shiftRight(2), p);  // Principal square root
        if (p.mod(EIGHT).equals(FIVE)) {
            // 2^((p−1)/4) is a square root of -1 modulo p
            BigInteger   d = n.modPow(p.subtract(ONE).shiftRight(2), p);
            return  d.equals(ONE)  ?  n.modPow(p.add(THREE).shiftRight(3), p)
                                   :  n.shiftLeft(1).multiply(
                                           n.shiftLeft(2).modPow(p.subtract(FIVE).shiftRight(3), p)).mod(p);
        }
        BigInteger  q = p.subtract(ONE),  ss = ZERO,  z = TWO;
        while (q.and(ONE).equals(ZERO)) {
            ss = ss.add(ONE);
            q = q.shiftRight(1);
        }

        while (!legendreSymbol(z, p).equals(p.subtract(ONE))) z = z.add(ONE);
        BigInteger   c = powModP.apply(z, q),  r = powModP.apply(n, q.add(ONE).shiftRight(1)),
                     t = powModP.apply(n, q),  m = ss;

        while (true) {
            if (t.equals(ONE))  return r;
            BigInteger   i = ZERO,  zz = t;
            while (!zz.equals(BigInteger.ONE) && i.compareTo(m.subtract(ONE)) < 0) {
                zz = zz.multiply(zz).mod(p);
                i = i.add(ONE);
            }
            BigInteger   b = c,  e = m.subtract(i).subtract(ONE);
            while (e.compareTo(ZERO) > 0) {
                b = b.multiply(b).mod(p);
                e = e.subtract(ONE);
            }
            r = r.multiply(b).mod(p);
            c = b.multiply(b).mod(p);
            t = t.multiply(c).mod(p);
            m = i;
        }
    }

    /**
     * Reconstructs {@code x mod pq} given {@code x mod p == a} and {@code x mod q == b}
     * @return {@code x mod pq}
     */
    static BigInteger  garnersFormula(BigInteger a, BigInteger p, BigInteger b, BigInteger q) {
        return  a.subtract(b).multiply(q.modInverse(p)).mod(p).multiply(q).add(b);
    }

    /**
     * Reconstructs the original composite integer based on its moduli using Garner's algorithm as elucidated
     * in Section 14.5.2 of "Handbook of Applied Cryptography" by A. Menezes, P. van Oorschot and S. Vanstone.
     * @param residues  a {@link List} each element i of which is a two element array consisting of residue, modulus
     *                  pairs
     * @return  the unique x as represented by the input parameter
     */
    public static BigInteger  garnersAlgorithm(List<BigInteger[]> residues) {
        int   n = residues.size();
        BigInteger   cVec[] = new BigInteger[n],  u,  x,  prd;
        for (int i=1; i < n; i++) {
            cVec[i] = ONE;
            for (int j=0; j < i; j++) {
                u = residues.get(j)[1].modInverse(residues.get(i)[1]);
                cVec[i] = cVec[i].multiply(u).mod(residues.get(i)[1]);
            }
        }
        x = u = residues.get(0)[0];
        for (int i=1; i < n; i++) {
            u = residues.get(i)[0].subtract(x).multiply(cVec[i]).mod(residues.get(i)[1]);
            prd = ONE;
            for (int j=0; j < i; j++) {
                prd = prd.multiply(residues.get(j)[1]);
            }
            x = u.multiply(prd).add(x);
        }

        return  x;
    }

    /**
     * Implements a recovery of e' from ep and eq as is explained in Section 4.1 of <a href="http://mpqs.free.fr/corr98-42.pdf">this paper</a>
     * @param ep  log<sub>s</sub>(pad(m)) mod p
     * @param eq  log<sub>s</sub>(pad(m)) mod q
     * @param pMin1  p-1
     * @param qMin1  q-1
     * @return  log<sub>s</sub>(pad(m)) mod pq
     */
    private static BigInteger  crt(BigInteger ep, BigInteger eq, BigInteger pMin1, BigInteger qMin1) {
        BigInteger   t = eq.subtract(ep).divide(TWO).multiply(pMin1.divide(TWO).modInverse(qMin1.divide(TWO))),
                lambda = pMin1.multiply(qMin1).divide(TWO);
        return  ep.add(t.multiply(pMin1)).mod(lambda);
    }

    static BigInteger  breakChallenge57(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException {
        DiffieHellman   bob = (DiffieHellman) Naming.lookup(url);
        DiffieHellmanHelperExt  dh = new DiffieHellmanHelperExt(P, G, Q);
        List<BigInteger>   factors = dh.findSmallFactors();
        int   n = factors.size();
        System.out.println(factors);

        BigInteger  prod = ONE;
        List<BigInteger[]>   residues = new ArrayList<>();
        Mac   mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);

        ANOTHER_MODULUS:
        for (int i=2; i < n; i++) {
            BigInteger   r = factors.get(i),  h = dh.findGenerator(r);
            Challenge57DHBobResponse   res = bob.initiate(P, G, Q, h);
            for (BigInteger b=ZERO; b.compareTo(r) < 0; b=b.add(ONE)) {  /* searching for Bob's secret key b modulo r */
                mac.init(dh.generateSymmetricKey(h, b, 32, MAC_ALGORITHM_NAME));
                if (Arrays.equals(res.mac, mac.doFinal(res.msg.getBytes())))  {
                    System.out.printf("Found b%d mod r%<d: %d, %d%n", residues.size(), b, r);
                    residues.add(new BigInteger[] {   b,  r   });
                    prod = prod.multiply(r);
                    if (prod.compareTo(Q) > 0)  {
                        System.out.printf("Enough found%n\tQ: %d%n\tP: %d%n", Q, prod);
                        break  ANOTHER_MODULUS;
                    }
                    break;
                }
            }
        }

        return  garnersAlgorithm(residues);
    }

    static BigInteger  breakChallenge58(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException {
        DiffieHellman   bob = (DiffieHellman) Naming.lookup(url);
        DiffieHellmanHelperExt   dh;
        BigInteger   p,  g,  q;
        List<BigInteger>   factors;
        int   n;

        do {                           /* We need at lease one factor greater than 10 */
            dh = DiffieHellmanHelperExt.newInstance();
            p = dh.getModulus();     g = dh.getGenerator();     q = dh.getGenOrder();
            factors = dh.findSmallFactors();
            n = factors.size();
        } while (factors.get(n-1).compareTo(TEN) < 0);

        System.out.println(factors);

        Mac   mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);

        // Using only the largest found factor rather than trying them all. This leads to a more realistic attack
        // vector for Bob is unlikely to hang on to the same private key across different sessions with Alice
        BigInteger   r = factors.get(n-1),  h = dh.findGenerator(r);
        Challenge57DHBobResponse   res = bob.initiate(p, g, q, h);
        for (BigInteger b=ZERO; b.compareTo(r) < 0; b=b.add(ONE)) {  /* searching for Bob's secret key b modulo r */
            mac.init(dh.generateSymmetricKey(h, b, 32, MAC_ALGORITHM_NAME));
            if (Arrays.equals(res.mac, mac.doFinal(res.msg.getBytes())))  {
                System.out.printf("Found b mod %d: %d%n", r, b);
                BigInteger  gPrime = g.pow(r.intValue()), yPrime = res.B.multiply(g.modPow(b.negate(), p)),
                        m = new DiffieHellmanHelper(p, gPrime).dlog(yPrime, q.subtract(ONE).divide(r), DiffieHellmanHelper::f);
                return  b.add(m.multiply(r));
            }
        }
        return  ZERO;
    }


    /**
     * @param base  a legitimate generator of the E(GF(p))
     * @param order  an order of {@code base}
     * @param url  the URL of Bob's RMI service
     * @return  Bob's private key
     */
    static BigInteger  breakChallenge59(WeierstrassECGroup.ECGroupElement base, BigInteger order, String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException {
        ECDiffieHellman   bob = (ECDiffieHellman) Naming.lookup(url);

        WeierstrassECGroup[]   degenerateGroups = {
                new WeierstrassECGroup(base.group().getModulus(), valueOf(-95051), valueOf(210),
                        new BigInteger("233970423115425145550826547352470124412"),
                        new BigInteger("116985211557712572775413273676235062206")),
                new WeierstrassECGroup(base.group().getModulus(), valueOf(-95051), valueOf(504),
                        new BigInteger("233970423115425145544350131142039591210")),
                new WeierstrassECGroup(base.group().getModulus(), valueOf(-95051), valueOf(727),
                        new BigInteger("233970423115425145545378039958152057148")),
        };
        SortedSet<BigInteger> factors = new TreeSet<>();
        BigInteger prod = ONE;
        List<BigInteger[]> residues = new ArrayList<>();
        Mac mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);

        ANOTHER_MODULUS:
        for (WeierstrassECGroup degenerateGroup : degenerateGroups) {
            List<BigInteger> newFactors = DiffieHellmanUtils.findSmallFactors(degenerateGroup.getOrder());
            newFactors.removeAll(factors);

            System.out.println(newFactors);

            for (BigInteger r : newFactors) {
                ECGroupElement h = degenerateGroup.findGenerator(r, false);
                Challenge59ECDHBobResponse res = bob.initiate(base, order, h);
                for (BigInteger b = ZERO; b.compareTo(r) < 0; b = b.add(ONE)) {  /* searching for Bob's secret key b modulo r */
                    mac.init(generateSymmetricKey(h, b, 32, MAC_ALGORITHM_NAME));
                    if (Arrays.equals(res.mac, mac.doFinal(res.msg.getBytes()))) {
                        System.out.printf("Found b%d mod %d: %d%n", residues.size(), r, b);
                        residues.add(new BigInteger[]{b, r});
                        prod = prod.multiply(r);
                        if (prod.compareTo(order) > 0) {
                            System.out.printf("Enough found%n\tQ: %d%n\tP: %d%n", order, prod);
                            break ANOTHER_MODULUS;
                        }
                        break;
                    }
                }
            }

            factors.addAll(newFactors);
        }
        return garnersAlgorithm(residues);
    }


    /**
     * Scans the range [0, {@code upper}] for a possible value of Bob's private key mod (order of generator h)
     * @param group  an elliptic curve group that
     * @param h the x-coordinate of a generator of a small subgroup of the quadratic twist of {@code group}
     * @param resp Bob's response to a DH protocol initiated by Alice, where h was presented to Bob as the x-coordinate
     *             of Alice's public key.
     */
    private static BigInteger  scanRangeForPrivateKeyPar(ExecutorService executor, BigInteger upper, MontgomeryECGroup group,
                                                         BigInteger h, Challenge60ECDHBobResponse resp) {
        BigInteger   freq = valueOf(1_000_000);
        AtomicBoolean   stop = new AtomicBoolean();
        Function<BigInteger[], BigInteger>   task = (range) -> {
            System.out.println(Thread.currentThread() + " is scanning range: " + Arrays.toString(range));
            try {
                Mac mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);
                for (BigInteger b = range[0]; b.compareTo(range[1]) <= 0; b = b.add(ONE)) {  /* searching for Bob's secret key b modulo r */
                    mac.init(generateSymmetricKey(group, h, b, 32, MAC_ALGORITHM_NAME));
                    if (b.remainder(freq).equals(ZERO)) {
                        System.out.printf("%s remaining range: [%d, %d]%n", Thread.currentThread(), b, range[1]);
                        if (stop.get())  return  null;
                    }
                    if (Arrays.equals(resp.mac, mac.doFinal(resp.msg.getBytes()))) {
                        return  stop.compareAndSet(false, true)  ?  b : null;
                    }
                }
            } catch (Exception e) {
                // ignore
            }
            return  null;
        };

        if (upper.compareTo(freq) <= 0)  {
            return  task.apply(new BigInteger[] { ZERO, upper });
        }

        int   concurrency = Runtime.getRuntime().availableProcessors();
        BigInteger   step = upper.divide(valueOf(concurrency)),  concur = valueOf(concurrency);

        List<CompletableFuture<BigInteger>>   res = IntStream.range(0, concurrency).mapToObj(BigInteger::valueOf).map(
                x -> CompletableFuture.completedFuture(
                        new BigInteger[] { x.multiply(step), x.add(ONE).equals(concur)
                                ?  upper : x.add(ONE).multiply(step).subtract(ONE) })).map(x -> x.thenApplyAsync(task, executor)).collect(Collectors.toList());
        for (CompletableFuture<BigInteger> future : res) {
            if (future.join() != null)  return  future.join();
        }
        return  null;
    }

    /**
     * @param base  a legitimate generator of the E(GF(p))
     * @param order  an order of {@code base}
     * @param url  the URL of Bob's RMI service
     * @return  Bob's private key
     */
    static List<BigInteger>  breakChallenge60(MontgomeryECGroup.ECGroupElement base, BigInteger order, String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException {
        ECDiffieHellman   bob = (ECDiffieHellman) Naming.lookup(url);
        BigInteger   rComp = ONE;
        List<BigInteger[]> residues = new ArrayList<>();
        Mac mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);

        List<BigInteger> factors = DiffieHellmanUtils.findSmallFactors(base.group().getTwistOrder(), 1 << 25);
        if (factors.isEmpty()) {
            throw new IllegalStateException("The twist of the elliptic curve " + base.group() + " has no small subgroups");
        }
        if (factors.get(0).equals(TWO)) {
            factors.remove(0);      // Handy in case the twist is not a cyclic group
            factors.set(0, factors.get(0).multiply(TWO));
        }
        System.out.println(factors);

        ExecutorService   executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        Challenge60ECDHBobResponse   resp;
        try {
            for (BigInteger r : factors) {
                BigInteger h = base.group().findTwistGenerator(r);
                System.out.printf("Generator of order %d found: %d%n", r, h);
                resp = bob.initiate(base, order, h);

                // Searching for Bob's secret key b modulo r in parallel
                BigInteger b = scanRangeForPrivateKeyPar(executor, r.divide(TWO), base.group(), h, resp);
                if (b != null) {
                    System.out.printf("Found b mod %d: %d or %d%n", r, b, r.subtract(b));
                    residues.add(new BigInteger[]{b, r});
                    rComp = rComp.multiply(r);

                    if (rComp.compareTo(order) >= 0) {
                        System.out.printf("Enough found%n\tQ: %d%n\tP: %d%n", order, rComp);
                        break;
                    }
                }
            }
        } finally {
            executor.shutdown();
        }

        CRTCombinations   crtCombs = new CRTCombinations(residues.toArray(new BigInteger[residues.size()][]));
        BigInteger   h = base.group().findTwistGenerator(rComp);
        System.out.printf("Generator of order %d found: %d%n", rComp, h);
        resp = bob.initiate(base, order, h);

        // We now have 2^residues.size() possible values of Bob's private key mod 'rComp'. We need to whittle it down to just 2.
        List<BigInteger>   cands = new ArrayList<>();
        for (BigInteger b : crtCombs) {
            System.out.printf("Trying %d mod %d as Bob's private key candidate. ", b, rComp);
            mac.init(generateSymmetricKey(base.group(), h, b, 32, MAC_ALGORITHM_NAME));
            if (Arrays.equals(resp.mac, mac.doFinal(resp.msg.getBytes()))) {
                cands.add(b);
                System.out.printf("Match%n");
            } else {
                System.out.printf("No match%n");
            }
        }

        // If Bob's private key == 0 mod some of the small primes, we may end up with duplicate candidates. Let's
        // get rid of them if there are any.
        if (cands.size() > 2)  cands = cands.stream().distinct().collect(Collectors.toList());
        assert  cands.size() == 2 : "Unexpected number of private key candidates";

        if (rComp.compareTo(order) >= 0)  return  cands; // Enough moduli, no need to take DLog in E(GF(p))

        ECGroupElement   gPrime = base.scale(rComp),
                         y = base.group().createPoint(resp.xB, base.group().mapToY(resp.xB));
        List<BigInteger>   ret = new ArrayList<>();

        for (BigInteger n : cands) {
            System.out.printf("Trying b mod %d = %d as Bob's private key%n", rComp, n);
            ECGroupElement   yPrime = y.combine(base.scale(order.subtract(n)));
            BigInteger   m = gPrime.dlog(yPrime, order.subtract(ONE).divide(rComp), ECGroupElement::f);
            n = n.add(m.multiply(rComp));
            ret.add(n);
            System.out.println("Possible private key: " + n);
        }
        return  ret;

    }

    @SneakyThrows
    public static SecretKeySpec generateSymmetricKey(ECGroupElement A, BigInteger b, int len, String keyAlgorithm) {
        MessageDigest sha = MessageDigest.getInstance(len > 20  ?  "SHA-256" : "SHA-1");
        return  new SecretKeySpec(Arrays.copyOf(sha.digest(A.scale(b).toByteArray()), len), keyAlgorithm);
    }

    public static SecretKeySpec generateSymmetricKey(ECGroup group, BigInteger xA, BigInteger b, int len, String keyAlgorithm) {
        // The uncommented code would be better from a security standpoint, but is not strictly required based
        // on how the challenge is formulated. It turns out to be too computationally intensive for Challenge 60
//        MessageDigest sha = MessageDigest.getInstance(len > 20  ?  "SHA-256" : "SHA-1");
//        return  new SecretKeySpec(Arrays.copyOf(sha.digest(group.ladder(xA, b).toByteArray()), len), keyAlgorithm);
        return  new SecretKeySpec(Arrays.copyOf(group.ladder(xA, b).toByteArray(), len), keyAlgorithm);
    }


    /**
     * Forges a public ECDSA key that is valid for a given message and ECDSA signature combination
     * @param msg  a message
     * @param signature  a valid ECDSA signature for {@code msg}
     * @param pk a public key whose corresponding private key was used to produce {@code signature}
     * @return a forged public key that validates the msg and signature combination
     */
    static ECDSA.PublicKey  breakChallenge61ECDSA(byte[] msg, DSAHelper.Signature signature, ECDSA.PublicKey pk) {
        BigInteger   w = signature.getS().modInverse(pk.getN()),  u1 = hashAsBigInteger(msg).multiply(w).mod(pk.getN()),
                     u2 = signature.getR().multiply(w).mod(pk.getN()),
                     d_ = DSAHelper.generateK(pk.getN()),
                     t = u1.add(u2.multiply(d_)).mod(pk.getN());
        ECGroupElement   R = pk.getG().scale(u1).combine(pk.getQ().scale(u2)),  G_= R.scale(t.modInverse(pk.getN())),
                         Q_ = G_.scale(d_);
        return  new ECDSA.PublicKey(G_, pk.getN(), Q_);
    }

    /**
     * Finds a DLog of {@code y} base {@code g} in group Z<sub>p</sub>* determined by prime {@code p}. The method
     * uses a combination of <a href="https://en.wikipedia.org/wiki/Pohlig–Hellman_algorithm">Pohlig-Hellman</a>
     * and Pollard's algorithms
     * @param y  an element of Zp* whose DLog base {@code g} needs to be found
     * @param g  a generator of Zp*
     * @param p  a prime defining  Zp*
     * @param factors  factors of {@code p - 1}
     */
    static BigInteger  findDLog(BigInteger y, BigInteger g, BigInteger p, List<BigInteger> factors) {
        List<BigInteger[]>   residues = new ArrayList<>();
        BigInteger   prod = ONE,  q;
        System.out.println(factors);

        for (BigInteger r : factors) {
            BigInteger   otherOrder = p.subtract(ONE).divide(r),
                         gi = g.modPow(otherOrder, p),  hi = y.modPow(otherOrder, p);
            for (BigInteger b = ZERO; b.compareTo(r) < 0; b = b.add(ONE)) {
                if (gi.modPow(b, p).equals(hi)) {
                    System.out.printf("Found b mod %d: %d%n", r, b);
                    residues.add(new BigInteger[]{b, r});
                    prod = prod.multiply(r);
                    break;
                }
            }
            if (prod.compareTo(p) >= 0) {
                System.out.printf("Enough found%n\tQ: %d%n\tP: %d%n", p, prod);
                break;
            }
        }

        q = garnersAlgorithm(residues);
        System.out.printf("b mod %d: %d%n", prod, q);

        if (prod.compareTo(p) < 0) {
            BigInteger  gPrime = g.modPow(prod, p),  yPrime = y.multiply(g.modPow(q.negate(), p)),
                    m = new DiffieHellmanHelper(p, gPrime).dlog(yPrime, p.subtract(ONE).divide(prod), DiffieHellmanHelper::f);

            System.out.printf("g^log(y) mod p = %d%ny mod p = %d%n", g.modPow(q.add(m.multiply(prod)), p), y.mod(p) );
            return  q.add(m.multiply(prod));
        }

        return  q;
    }

    /**
     * Finds primes p and q meeting the following requirements:
     * <ol>
     *     <li> p-1 and q-1 are smooth
     *     <li> both s and pad(m) ({@code s^e = pad(m) mod N}) are generators of the entire Zp* and Zq* groups</li>
     *     <li> gcd(p-1, q-1)=2</li>
     * </ol>
     * @param padm  a PKCS#1 v1.5 mode 1 padded message
     * @param sign  an RSA signature of {@code padm}
     * @param bitLength  the bit length of the RSA modulus that was used to produce {@code sign}
     * @return suitable primes along with the factors of their Zp*, Zq* group orders
     */
    private static DiffieHellmanUtils.PrimeAndFactors[]  searchForPQPar(BigInteger padm, BigInteger sign, int bitLength) {
        final int   freq = 10;
        final int   smallPrimes[] = DiffieHellmanUtils.findSmallPrimes((1 << 20) + (1 << 16));

        // minProd is a heuristically established minimum product of factors to make DLog tractable
        final BigInteger   minProd = new BigInteger("3700000000000000000000000000000000");
        DiffieHellmanUtils.PrimeAndFactors[]  res = new DiffieHellmanUtils.PrimeAndFactors[2];
        AtomicBoolean   stop = new AtomicBoolean();

        Runnable   task = () -> {
            System.out.println(Thread.currentThread() + " is searching");
            DiffieHellmanUtils.PrimeAndFactors   primeAndFactors;
            BigInteger   product;
            int   i = 0;

            while (true) {
                do {
                    if (++i % freq == 0) {
                        System.out.println(Thread.currentThread() + " sieved through another " + freq + " primes");
                        if (stop.get())  return;
                    }
                    // An extra bit to ensure the product is at least bitLength long
                    primeAndFactors = DiffieHellmanUtils.findSmoothPrime(bitLength / 2 + 1, smallPrimes);
                    product = primeAndFactors.getFactors().stream().reduce(ONE, BigInteger::multiply);
                } while (product.compareTo(minProd) < 0
                        || !DiffieHellmanUtils.isPrimitiveRoot(padm, primeAndFactors.getP(), primeAndFactors.getFactors())
                        || !DiffieHellmanUtils.isPrimitiveRoot(sign, primeAndFactors.getP(), primeAndFactors.getFactors()));

                synchronized (res) {
                    if (res[0] == null) {
                        res[0] = primeAndFactors;
                        System.out.println("One prime found: " + primeAndFactors);
                    } else {
                        // The only shared factor between p-1 and q-1 must be 2
                        if (primeAndFactors.getP().subtract(ONE).gcd(res[0].getP().subtract(ONE)).equals(TWO)) {
                            if (res[1] == null) {
                                res[1] = primeAndFactors;
                            }
                            stop.set(true);
                            return;
                        }
                    }
                }
            }
        };

        int   concurrency = Runtime.getRuntime().availableProcessors();
        ExecutorService   executor = Executors.newFixedThreadPool(concurrency);

        CompletableFuture.anyOf(IntStream.range(0, concurrency)
                .mapToObj(x -> CompletableFuture.runAsync(task, executor)).toArray(CompletableFuture[]::new)).join();

        executor.shutdown();
        return  res;
    }


    /**
     * @param pq   an already precomputed suitable p and q primes that meet the requirements for 1) {@code p-1} and {@code q-1}
     *             being smooth and 2) both {@code rsaSignature} and {@code pad(msg)} being generators of the entire
     *             Zp* and Zq* groups.
     * @param bitLength   number of bits in the RSA modulus that was used to calculate {@code rsaSignature}
     */
    static RSAHelper.PublicKey  breakChallenge61RSA(byte[] msg, BigInteger rsaSignature,
                                                    DiffieHellmanUtils.PrimeAndFactors[] pq, int bitLength) {
        BigInteger   padm = RSAHelperExt.pkcs15Pad(msg, RSAHelperExt.HashMethod.SHA1, bitLength);

        System.out.println("Modulus bitLength: " + bitLength);
        System.out.println("p * q bitLength: " + pq[0].getP().multiply(pq[1].getP()).bitLength());
        if (!DiffieHellmanUtils.isPrimitiveRoot(rsaSignature, pq[0].getP(), pq[0].getFactors())
            ||  !DiffieHellmanUtils.isPrimitiveRoot(rsaSignature, pq[1].getP(), pq[1].getFactors())
            ||  !DiffieHellmanUtils.isPrimitiveRoot(padm, pq[0].getP(), pq[0].getFactors())
            ||  !DiffieHellmanUtils.isPrimitiveRoot(padm, pq[1].getP(), pq[1].getFactors())) {
            throw  new IllegalArgumentException("Primes p and q don't meet the requirement of ");
        }

        BigInteger   logs[] = Stream.of(pq).parallel()
                .map(x -> findDLog(padm, rsaSignature, x.getP(), x.getFactors())).toArray(BigInteger[]::new);

        System.out.println("s: " + rsaSignature);
        System.out.println("pad(m): " + padm);
        System.out.println("p: " + pq[0].getP());
        System.out.println("q: " + pq[1].getP());
        System.out.println("logP: " + logs[0]);
        System.out.println("logQ: " + logs[1]);

        System.out.printf("s^logs(pad(m)) mod p: %d%ns^logs(pad(m)) mod q: %d%n",
                rsaSignature.modPow(logs[0], pq[0].getP()),
                rsaSignature.modPow(logs[1], pq[1].getP()));

        System.out.printf("pad(msg) mod p: %d%npad(msg) mod q: %d%n",
                padm.mod(pq[0].getP()),
                padm.mod(pq[1].getP()) );

        System.out.printf("s^log(p) = pad(msg) mod p: %b%ns^log(q) = pad(msg) mod q: %b%n",
                rsaSignature.modPow(logs[0], pq[0].getP()).equals(padm.mod(pq[0].getP())),
                rsaSignature.modPow(logs[1], pq[1].getP()).equals(padm.mod(pq[1].getP())));


        return  new RSAHelper.PublicKey(crt(logs[0], logs[1], pq[0].getP().subtract(ONE), pq[1].getP().subtract(ONE)),
                                        pq[0].getP().multiply(pq[1].getP()));
    }


    /**
     * @param bitLength   number of bits in the RSA modulus that was used to calculate {@code rsaSignature}
     */
    static RSAHelper.PublicKey  breakChallenge61RSA(byte[] msg, BigInteger rsaSignature, int bitLength) {
        BigInteger   padm = RSAHelperExt.pkcs15Pad(msg, RSAHelperExt.HashMethod.SHA1, bitLength);
        DiffieHellmanUtils.PrimeAndFactors[]   primeAndFactors = searchForPQPar(padm, rsaSignature, bitLength);

        System.out.println("Suitable primes found: " + Arrays.toString(primeAndFactors));
        return  breakChallenge61RSA(msg, rsaSignature, primeAndFactors, bitLength);
    }

    /**
     * Utility for debugging purposes in Challenge 66.
     */
    static void  trace(ECGroupElement point, BigInteger k) {
        System.out.println("# k = " + k.toString(16));
        BigInteger   coef = ONE;
        int   n = k.bitLength();
        ECGroupElement res = point;
        try {
            for (int i=n-2; i >= 0; i--) {
                System.out.printf("# i = %d, b = %d%n", n - i, k.testBit(i) ? 1 : 0);
                System.out.printf("add(%dQ, %<dQ)%n", coef);
                res = res.combine(res);
                coef = coef.shiftLeft(1);
                if (k.testBit(i)) {
                    System.out.printf("add(%dQ, 1Q)%n", coef);
                    res = res.combine(point);
                    coef = coef.add(ONE);
                }
            }
        } catch (IllegalStateException e) {
            System.out.println("Fault raised");
        }
    }

    /**
     * A special version of scale required to mount the attack from Challenge 66.
     */
    private static ECGroupElement  scaleForChallenge66(ECGroupElement point, BigInteger k, int idx) {
        int   n = k.bitLength();
        ECGroupElement   res = point;
        if (idx > 0)  res = res.combine(res);
        for (int i=n-2; i >= Math.max(idx, 1); i--) try {
            if (k.testBit(i))  {
                res = res.combine(point);
            }
            res = res.combine(res);
        } catch (IllegalStateException e) {
            if (i == idx)  throw e;
            return  null;
        }
        if (idx == 0) {
            if (k.testBit(0)) {
                res = res.combine(point);
            }
        }
        return  res;
    }

    /**
     * @param group  an elliptic curve group whose elements might raise a fault upon invoking their {@code combine} method
     * @param pk  a private key whose {@code pk.bitLength() - 1 - idx} most significant bits have been recovered
     * @param idx  the index of the private key that should trigger a fault
     * @param isLeftBranch  a one-element boolean array that will be modified by this method to indicate which branch triggers
     *                   a fault (left when bit with index {@code idx} is not set, right otherwise)
     * @return  a point on {@code group} that will trigger a fault when scaled to {@code pk} or {@code pk.setBit(idx)}
     */
    static FaultyWeierstrassECGroup.ECGroupElement  findPointWithFaultAtBitIndex(FaultyWeierstrassECGroup group,
                                                                                 BigInteger pk, int idx, boolean[] isLeftBranch) {
        FaultyWeierstrassECGroup.ECGroupElement   res;
        int   tries = 0;
        // Instead of simulating only the b = 0 branch, simulate both branches.
        // Find a candidate point that triggers a fault on one but not the other.
        boolean   leftBranchTriggeredFault,  rightBranchTriggeredFault;
        do {
            leftBranchTriggeredFault = rightBranchTriggeredFault = false;
            res = group.createRandomPoint();
            try {
                scaleForChallenge66(res, pk, idx);
            } catch (IllegalStateException ignore) {
                leftBranchTriggeredFault = true;
            }
            try {
                scaleForChallenge66(res, pk.setBit(idx), idx);
            } catch (IllegalStateException ignore) {
                rightBranchTriggeredFault = true;
            }
            tries++;
        } while (leftBranchTriggeredFault == rightBranchTriggeredFault);
        System.out.printf("Point found after %d tries%n", tries);
        isLeftBranch[0] = leftBranchTriggeredFault;
        return  res;
    }

    /**
     * @param base  a legitimate generator of the E(GF(p))
     * @param order  an order of {@code base}
     * @param url  the URL of Bob's RMI service
     * @return  Bob's private key
     */
    static BigInteger  breakChallenge66(FaultyWeierstrassECGroup.ECGroupElement base, BigInteger order, String url,
                                        BigInteger incidence)
            throws RemoteException, NotBoundException, MalformedURLException {
        ECDiffieHellman   bob = (ECDiffieHellman) Naming.lookup(url);

        FaultyWeierstrassECGroup   group = base.group();
        int   idxMSB = order.bitLength() - 1,  idx = idxMSB - 1;
        BigInteger   pk = ONE.shiftLeft(idxMSB);
        boolean[]   isLeftBranch = {   false   };
        // double    probability = 1 - 1 / incidence.doubleValue();

        while (idx >= 0) {
            FaultyWeierstrassECGroup.ECGroupElement   point = findPointWithFaultAtBitIndex(group, pk, idx, isLeftBranch);
            try {
                bob.initiate(base, order, point);
            } catch (IllegalStateException ex) {
                // Even in the presence of uncertainty, positive results have value. You can calculate the probability
                // of a false positive and determine whether you have enough confidence to proceed.
                //
                // The maximum possible number of tries after this idx is numSteps = 2 * idx.
                // The low bound on the probability of no faults in these following steps is (1-1/incidence)^numSteps
                /*if (Math.pow(probability, idx << 1) > .9999) {
                    if (!isLeftBranch[0]) {
                        pk = pk.setBit(idx);
                    }
                }  else*/  continue;
            }

            // The left branch was supposed to trigger a fault and there's no fault, therefore the right branch got
            // executed so bit index idx needs to be set
            if (isLeftBranch[0]) {
                pk = pk.setBit(idx);
            }
            System.out.println("Recovered bit index # " + idx);
            System.out.println("pk: " + pk.toString(16));
            idx--;
        }

        return  pk;
    }


    /**
     * Generates a piece of plain text composed of repeating the pattern captured in {@code str} so that the resultant
     * piece of text is 2<sup>exp</sup> + lengthAdj characters long.
     */
    public static byte[]  getPlainText(String str, int exp, int lengthAdj) {
        StringBuilder   res = new StringBuilder();
        int  i = 0,  n = (1 << exp) + lengthAdj;
        while (i < n) {
            int   len = Math.min(n - i, str.length());
            res.append(str, 0, len);
            i += len;
        }
        return  res.toString().getBytes();
    }

    /**
     * Generates a piece of plain text composed of random ASCII-32-95 characters so that the resultant
     * piece of text is 2<sup>exp</sup> characters long.
     */
    public static byte[]  getPlainText(int exp) {
        Random   rnd = new SecureRandom();
        StringBuilder   res = new StringBuilder();
        int  i = 0,  n = 1 << exp;
        while (i++ < n) {
            res.append((char) (32 + rnd.nextInt(95)));
        }
        return  res.toString().getBytes();
    }

    public static void main(String[] args) {

        try {
            System.out.println("Challenge 57");
            String   bobUrl = "rmi://localhost/DiffieHellmanBobService";

            BigInteger   test[][] = {
                    {  BigInteger.valueOf(2),  BigInteger.valueOf(5) },
                    {  BigInteger.valueOf(1),  BigInteger.valueOf(7) },
                    {  BigInteger.valueOf(3),  BigInteger.valueOf(11) },
                    {  BigInteger.valueOf(8),  BigInteger.valueOf(13) },
            };

            assert  garnersAlgorithm(Arrays.asList(test)).equals(BigInteger.valueOf(2192));

            BigInteger   b = breakChallenge57("rmi://localhost/DiffieHellmanBobService");
            DiffieHellman   bob = (DiffieHellman) Naming.lookup(bobUrl);

            assert  bob.isValidPrivateKey(b) : "Bob's key not correct";
            System.out.printf("Recovered Bob's secret key: %x%n", b);

            System.out.println("\nChallenge 58");
            DiffieHellmanHelper  dh = new DiffieHellmanHelper(
                    new BigInteger("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623"),
                    new BigInteger("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357"));

            BigInteger   y = new BigInteger("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119");
            b = dh.dlog(y, valueOf(2).pow(20), DiffieHellmanHelper::f);
            System.out.printf("Recovered dlog of %d:%n %d%n", y, b);
            assert  dh.getGenerator().modPow(b, dh.getModulus()).equals(y);

            y = new BigInteger("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733");
            b = dh.dlog(y, valueOf(2).pow(40), DiffieHellmanHelper::f);
            System.out.printf("Recovered dlog of %d:%n %d%n", y, b);
            assert  dh.getGenerator().modPow(b, dh.getModulus()).equals(y);

//            b = breakChallenge58("rmi://localhost/DiffieHellmanBobService");
//            assert  bob.isValidPrivateKey(b) : "Bob's key not correct";
//            System.out.printf("Recovered Bob's secret key: %x%n", b);

            System.out.println("\nChallenge 59");
            WeierstrassECGroup group = new WeierstrassECGroup(new BigInteger("233970423115425145524320034830162017933"),
                    valueOf(-95051), valueOf(11279326), new BigInteger("233970423115425145498902418297807005944"));
            WeierstrassECGroup.ECGroupElement   base = group.createPoint(
                    valueOf(182), new BigInteger("85518893674295321206118380980485522083"));
            BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
            assert  group.containsPoint(base);
            assert  base.scale(q) == group.O;

            bobUrl = "rmi://localhost/ECDiffieHellmanBobService";
            BigInteger   privateKeyAlice = new DiffieHellmanHelper(group.getModulus(), q).generateExp().mod(q);
            ECDiffieHellman   ecBob = (ECDiffieHellman) Naming.lookup(bobUrl);
            Challenge59ECDHBobResponse  res = ecBob.initiate(base, q, base.scale(privateKeyAlice));
            Mac   mac = Mac.getInstance(MAC_ALGORITHM_NAME);
            SecretKey   macKey = generateSymmetricKey(res.B, privateKeyAlice, 32, MAC_ALGORITHM_NAME);
            mac.init(macKey);
            assert  Arrays.equals(mac.doFinal(res.msg.getBytes()), res.mac);
            System.out.println("DiffieHellman in the EC " + group + " works");

            b = breakChallenge59(base, q, bobUrl);
            assert  ecBob.isValidPrivateKey(b) : "Bob's key not correct";
            System.out.printf("Recovered Bob's secret key: %x%n", b);

            System.out.println("\nChallenge 60");
            MontgomeryECGroup   mgroup = new MontgomeryECGroup(new BigInteger("233970423115425145524320034830162017933"),
                    valueOf(534), ONE, new BigInteger("233970423115425145498902418297807005944"));
            MontgomeryECGroup.ECGroupElement   mbase = mgroup.createPoint(
                    valueOf(4), new BigInteger("85518893674295321206118380980485522083"));

            BigInteger   exponent = valueOf(12130);
            assert  exponent.equals(mbase.dlog(mbase.scale(exponent), valueOf(1110000), ECGroupElement::f));

            assert  ZERO.equals(mbase.ladder(q));
            System.out.println("base^q = " + mbase.scale(q));
            System.out.println("base^q-1 = " + mbase.scale(q.subtract(ONE)));
            System.out.println("base^q-2 = " + mbase.scale(q.subtract(TWO)));
            System.out.println("base^q+1 = " + mbase.scale(q.add(ONE)));

            for (BigInteger bb : breakChallenge60(mbase, q, bobUrl)) {
                System.out.printf("Recovered Bob's secret key: %d? %b%n", bb, ecBob.isValidPrivateKey(bb));
            }

            System.out.println("\nChallenge 61");
            // Curve 25519
            MontgomeryECGroup   curve25519 = new MontgomeryECGroup(CURVE_25519_PRIME,
                    valueOf(486662), ONE, CURVE_25519_ORDER, CURVE_25519_ORDER.shiftRight(3));
            MontgomeryECGroup.ECGroupElement   curve25519Base = curve25519.createPoint(
                    valueOf(9), curve25519.mapToY(valueOf(9)));
            q = curve25519.getCyclicOrder();
            System.out.println("base^q = " + curve25519Base.scale(q));
            System.out.println("base^q-1 = " + curve25519Base.scale(q.subtract(ONE)));
            System.out.println("base^q-2 = " + curve25519Base.scale(q.subtract(TWO)));
            System.out.println("base^q+1 = " + mbase.scale(q.add(ONE)));
            System.out.println("ladder(q) = " + curve25519Base.ladder(q));

            ECDSA   ecdsa = new ECDSA(curve25519Base, q);
            DSAHelper.Signature   signature = ecdsa.sign(CHALLENGE56_MSG.getBytes());
            ECDSA.PublicKey   legitPk = ecdsa.getPublicKey(),
                              forgedPk = breakChallenge61ECDSA(CHALLENGE56_MSG.getBytes(), signature, ecdsa.getPublicKey());
            assert  legitPk.verifySignature(CHALLENGE56_MSG.getBytes(), signature);
            assert  forgedPk.verifySignature(CHALLENGE56_MSG.getBytes(), signature);
            assert  !legitPk.equals(forgedPk);
            System.out.println("Legit public key: " + legitPk);
            System.out.println("Forged public key: " + forgedPk);


            RSAHelperExt rsa = new RSAHelperExt(RSAHelper.PUBLIC_EXPONENT, 160);
            BigInteger rsaSignature = rsa.sign(CHALLENGE56_MSG.getBytes(), RSAHelperExt.HashMethod.SHA1);

            RSAHelper.PublicKey legitRSAPk = rsa.getPublicKey(),
                    forgedRSAPk = breakChallenge61RSA(CHALLENGE56_MSG.getBytes(), rsaSignature,
                        legitRSAPk.getModulus().bitLength());

            System.out.println("Does legit key verify?: " + legitRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
            System.out.println("Does forged key verify?: " + forgedRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));

            assert legitRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature);
            assert forgedRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
