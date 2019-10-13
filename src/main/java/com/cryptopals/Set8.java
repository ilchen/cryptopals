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
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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
            CURVE_25519_ORDER = ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger   TWO = valueOf(2),  THREE = valueOf(3),  FOUR = valueOf(4);

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
     * Finds &radic;n mod p using <a href="https://en.wikipedia.org/wiki/Tonelli–Shanks_algorithm">the Tonelli–Shanks algorithm</a>
     * @return  &radic;n mod p if n is a quadratic residue, {@link #NON_RESIDUE} otherwise
     */
    static public BigInteger  squareRoot(BigInteger n, BigInteger p) {
        BiFunction<BigInteger, BigInteger, BigInteger>   powModP = (BigInteger a, BigInteger e) -> a.modPow(e, p);
        Function<BigInteger, BigInteger>   ls = (BigInteger a) -> powModP.apply(a, p.subtract(ONE).divide(TWO));
        if (!ls.apply(n).equals(ONE))   return  NON_RESIDUE;
        if (p.mod(FOUR).equals(THREE))  return  powModP.apply(n, p.add(ONE).divide(FOUR));

        BigInteger  q = p.subtract(ONE),  ss = ZERO,  z = TWO;
        while (q.and(ONE).equals(ZERO)) {
            ss = ss.add(ONE);
            q = q.shiftRight(1);
        }

        while (!ls.apply(z).equals(p.subtract(ONE))) z = z.add(ONE);
        BigInteger   c = powModP.apply(z, q),  r = powModP.apply(n, q.add(ONE).divide(TWO)),
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
     * @param residues  an {@link List} each element i of which is a two element array consisting of residue, modulus
     *                  pairs
     * @return  the unique x as represented by the input parameter
     */
    static BigInteger  garnersAlgorithm(List<BigInteger[]> residues) {
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
        // vector for Bob is unlikely to hang on to the same private key across diferent sessions with Alice
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
                ECGroupElement h = degenerateGroup.findGenerator(r);
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
                for (BigInteger b = range[0]; b.compareTo(range[1]) < 0; b = b.add(ONE)) {  /* searching for Bob's secret key b modulo r */
                    mac.init(generateSymmetricKey(group, h, b, 32, MAC_ALGORITHM_NAME));
                    if (b.remainder(freq).equals(ZERO)) {
                        System.out.printf("%s remaining range: [%d, %d)%n", Thread.currentThread(), b, range[1]);
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
                                ?  upper : x.add(ONE).multiply(step) })).map(x -> x.thenApplyAsync(task, executor)).collect(Collectors.toList());
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

        BigInteger prod = ONE,  x[] = new BigInteger[4];
        List<BigInteger[]> residues = new ArrayList<>();
        Mac mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);


        List<BigInteger> factors = DiffieHellmanUtils.findSmallFactors(base.group().getTwistOrder(), 1 << 25);
        if (factors.isEmpty()) {
            throw new IllegalStateException("The twist of the elliptic curve " + base.group() + " has no small subgroups");
        }
        if (factors.get(0).equals(TWO)) {
            factors.remove(0);      // Handy in case the twist is not a cyclic group
        }

        ExecutorService   executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        CRTCombinations   crtCombs = new CRTCombinations(factors.size());
        Challenge60ECDHBobResponse   resp = null;

        System.out.println(factors);

        ANOTHER_MODULUS:
        for (int i=0; i < factors.size(); i++) {
            BigInteger r = factors.get(i);
            BigInteger h = base.group().findTwistGenerator(r);
            System.out.printf("Generator of order %d found: %d%n", r, h);
            resp = bob.initiate(base, order, h);
            for (BigInteger b = ZERO; b.compareTo(r) < 0; b = b.add(ONE)) {  /* searching for Bob's secret key b modulo r */
                mac.init(generateSymmetricKey(base.group(), h, b, 32, MAC_ALGORITHM_NAME));
                if (Arrays.equals(resp.mac, mac.doFinal(resp.msg.getBytes()))) {
                    System.out.printf("Found b mod %d: %d or %d%n", r, b, r.subtract(b));
                    residues.add(new BigInteger[]{b, r});
                    crtCombs.addResidue(i, b, r);
                    prod = prod.multiply(r);

                    if (residues.size() > 1) {
                        int   _i = residues.size() - 2;
                        BigInteger   _b = residues.get(_i)[0],
                                     _r = residues.get(_i)[1],
                                     comp = r.multiply(_r),  bb;

                        if (_r.compareTo(CHALLENGE60_COMPOSITE_MODULI_THREASHOLD) > 0
                                &&  r.compareTo(CHALLENGE60_COMPOSITE_MODULI_THREASHOLD) > 0) {
                            // It will be too computationally intensive to find the b mod comp
                            crtCombs.addMutation(i, CRTCombinations.MutationType.ONE);
                            break;
                        }

                        h = base.group().findTwistGenerator(comp);
                        resp = bob.initiate(base, order, h);
                        bb = scanRangeForPrivateKeyPar(executor, comp.divide(TWO), base.group(), h, resp);

                        //System.out.printf("Found b mod %d: %d or %d%n", comp, bb, comp.subtract(bb));
                        x[0] = garnersFormula(_b, _r, b, r);
                        x[1] = garnersFormula(_b, _r, r.subtract(b), r);
//                        x[2] = garnersFormula(_r.subtract(_b), _r, b, r);
//                        x[3] = garnersFormula(_r.subtract(_b), _r, r.subtract(b), r);

                        if (b.equals(ZERO)  &&  !_b.equals(ZERO)) {
                            crtCombs.addMutation(i - 1, CRTCombinations.MutationType.ONE);
                        } else if (_b.equals(ZERO)  &&  !b.equals(ZERO)) {
                            crtCombs.addMutation(i, CRTCombinations.MutationType.ONE);
                        } else if (x[0].equals(bb) || x[0].equals(comp.subtract(bb))) {
                            crtCombs.addMutation(i - 1, CRTCombinations.MutationType.BOTH);
                        } else if (x[1].equals(bb) || x[1].equals(comp.subtract(bb))) {
                            crtCombs.addMutation(i - 1, CRTCombinations.MutationType.EITHER);
                        } else {
                            System.out.printf("No match: _b=%d, _r=%d, b=%d, r=%d, bb=%d, comp=%d%n", _b, _r, b, r, bb, comp);
                        }
                        break;
                    }
                    if (prod.compareTo(order) >= 0) {
                        System.out.printf("Enough found%n\tQ: %d%n\tP: %d%n", order, prod);
                        break ANOTHER_MODULUS;
                    }
                    break;
                }
            }
        }

        executor.shutdown();
        List<BigInteger>   ret = new ArrayList<>();
        for (BigInteger[][] _residues : crtCombs) {
            System.out.println(Arrays.deepToString(_residues));
        }

        for (BigInteger[][] _residues : crtCombs) {
            if (_residues == null)  break;
            System.out.println(Arrays.deepToString(_residues));
            BigInteger   res = garnersAlgorithm(Arrays.asList(_residues));
            System.out.printf("b mod %d = %d%n", prod, res);

            if (prod.compareTo(order) < 0) {   // Not enough moduli, need to take DLog in E(GF(p))
                ECGroupElement gPrime = base.scale(prod),
                        yPrime = base.group().createPoint(resp.xB, base.group().mapToY(resp.xB)).combine(base.scale(order.subtract(res)));
                BigInteger m = base.dlog(yPrime, order.subtract(ONE).divide(prod), ECGroupElement::f);
                res.add(m.multiply(prod));
            }
            ret.add(res);
            System.out.println("Possible private key: " + res);
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
     * Finds a DLog of {@code y} base {@code g} in group Zp* determined by prime {@code p}. The method
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
        int   n = factors.size();
        System.out.println(factors);

        ANOTHER_MODULUS:
        for (int i=0; i < n; i++) {
            BigInteger   r = factors.get(i), otherOrder = p.subtract(ONE).divide(r),
                         gi = g.modPow(otherOrder, p),  hi = y.modPow(otherOrder, p);
            for (BigInteger b=ZERO; b.compareTo(r) < 0; b=b.add(ONE)) {
                if (gi.modPow(b, p).equals(hi)) {
                    System.out.printf("Found b mod %d: %d%n", r, b);
                    residues.add(new BigInteger[] { b, r });
                    prod = prod.multiply(r);
                    break;
                }
            }
            if (prod.compareTo(p) >= 0)  {
                System.out.printf("Enough found%n\tQ: %d%n\tP: %d%n", p, prod);
                break  ANOTHER_MODULUS;
            }
        }

        q = garnersAlgorithm(residues);
        System.out.printf("b mod %d: %d%n", prod, q);

        if (prod.compareTo(p) < 0) {
            BigInteger  gPrime = g.modPow(prod, p),  yPrime = y.multiply(g.modPow(q.negate(), p)),
                    m = new DiffieHellmanHelper(p, gPrime).dlog(yPrime, p.subtract(ONE).divide(prod), DiffieHellmanHelper::f);
            return  q.add(m.multiply(prod));
        }

        return  q;
    }

    /**
     * @param bitLength   number of bits in the RSA modulus that was used to calculate {@code rsaSignature}
     */
    static RSAHelper.PublicKey  breakChallenge61RSA(byte[] msg, BigInteger rsaSignature, int bitLength) {
        DiffieHellmanUtils.PrimeAndFactors   primeAndFactorsP,  primeAndFactorsQ = null;
        BigInteger   padm = RSAHelperExt.pkcs15Pad(msg, RSAHelperExt.HashMethod.SHA1, bitLength),  N_,  logP,  logQ;
        do {
            primeAndFactorsP = DiffieHellmanUtils.findSmoothPrime2(bitLength / 2);
        }  while (!DiffieHellmanUtils.isPrimitiveRoot(padm, primeAndFactorsP.getP(), primeAndFactorsP.getFactors())
                || !DiffieHellmanUtils.isPrimitiveRoot(rsaSignature, primeAndFactorsP.getP(), primeAndFactorsP.getFactors()));

        System.out.println("One found: " + primeAndFactorsP.getFactors());
        do {
            primeAndFactorsQ = DiffieHellmanUtils.findSmoothPrime2(bitLength / 2);
        } while (!DiffieHellmanUtils.isPrimitiveRoot(padm, primeAndFactorsQ.getP(), primeAndFactorsQ.getFactors())
                ||  !DiffieHellmanUtils.isPrimitiveRoot(rsaSignature, primeAndFactorsQ.getP(), primeAndFactorsQ.getFactors()));

        System.out.printf("Found desired p and q:%n\t%d%n\t%d%n", primeAndFactorsP.getP(), primeAndFactorsQ.getP());
        N_ = primeAndFactorsP.getP().multiply(primeAndFactorsQ.getP());


        logP = findDLog(padm, rsaSignature, primeAndFactorsP.getP(), primeAndFactorsP.getFactors());
        System.out.println("logP: " + logP);

        logQ = findDLog(padm, rsaSignature, primeAndFactorsQ.getP(), primeAndFactorsQ.getFactors());
        System.out.println("logQ: " + logQ);

        return  new RSAHelper.PublicKey(garnersFormula(logP, primeAndFactorsP.getP(), logQ, primeAndFactorsQ.getP()), N_);
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

//            y = new BigInteger("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733");
//            b = dh.dlog(y, valueOf(2).pow(40), DiffieHellmanHelper::f);
//            System.out.printf("Recovered dlog of %d:%n %d%n", y, b);
//            assert  dh.getGenerator().modPow(b, dh.getModulus()).equals(y);

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

//            b = breakChallenge59(base, q, bobUrl);
//            assert  ecBob.isValidPrivateKey(b) : "Bob's key not correct";
//            System.out.printf("Recovered Bob's secret key: %x%n", b);

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

//            for (BigInteger bb : breakChallenge60(mbase, q, bobUrl)) {
//                System.out.printf("Recovered Bob's secret key: %d? %b%n", bb, ecBob.isValidPrivateKey(b));
//            }

            System.out.println("\nChallenge 61");
            // Curve 25519
            MontgomeryECGroup   curve25519 = new MontgomeryECGroup(CURVE_25519_PRIME,
                    valueOf(486662), ONE, CURVE_25519_ORDER.shiftRight(3), CURVE_25519_ORDER);
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

            RSAHelperExt   rsa = new RSAHelperExt(valueOf(3), 160);
            BigInteger   rsaSignature = rsa.sign(CHALLENGE56_MSG.getBytes(), RSAHelperExt.HashMethod.SHA1);
            RSAHelper.PublicKey   legitRSAPk = rsa.getPublicKey(),
                                  forgedRSAPk = breakChallenge61RSA(CHALLENGE56_MSG.getBytes(), rsaSignature,
                                                                    legitRSAPk.getModulus().bitLength());
            assert  legitRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature);
            assert  forgedRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
