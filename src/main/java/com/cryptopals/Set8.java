package com.cryptopals;

import com.cryptopals.set_5.DiffieHellmanHelper;
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
import java.util.function.BiFunction;
import java.util.function.Function;

import static java.math.BigInteger.*;

/**
 * Created by Andrei Ilchenko on 28-07-19.
 */
public class Set8 {
    public static final String   CHALLENGE56_MSG = "crazy flamboyant for the rap enjoyment";
    public static final String   MAC_ALGORITHM_NAME = "HmacSHA256";
    public static final BigInteger   NON_RESIDUE = valueOf(-1);
    static final BigInteger   P = new BigInteger(
            "7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475"
            + "480089726140708102474957429903531369589969318716771"),
                              G = new BigInteger(
             "45653563970957406554368545034838268321361061416395634877324381953436904376061178"
             + "28318042418238184896212352329118608100083187535033402010599512641674644143"),
                              Q = new BigInteger("236234353446506858198510045061214171961");
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
                        new BigInteger("233970423115425145550826547352470124412")),
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

            int n = newFactors.size();
            System.out.println(newFactors);

            for (int i = 0; i < n; i++) {
                BigInteger r = newFactors.get(i);
                if (r.equals(TWO))  continue;
                ECGroupElement h = degenerateGroup.findGenerator(r);
                Challenge59ECDHBobResponse res = bob.initiate(base, order, h);
                for (BigInteger b = ZERO; b.compareTo(r) < 0; b = b.add(ONE)) {  /* searching for Bob's secret key b modulo r */
                    mac.init(generateSymmetricKey(h, b, 32, MAC_ALGORITHM_NAME));
                    if (Arrays.equals(res.mac, mac.doFinal(res.msg.getBytes()))) {
                        System.out.printf("Found b%d mod r%<d: %d, %d%n", residues.size(), b, r);
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
     * @param base  a legitimate generator of the E(GF(p))
     * @param order  an order of {@code base}
     * @param url  the URL of Bob's RMI service
     * @return  Bob's private key
     */
    static BigInteger  breakChallenge60(MontgomeryECGroup.ECGroupElement base, BigInteger order, String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException {
        ECDiffieHellman   bob = (ECDiffieHellman) Naming.lookup(url);


        BigInteger prod = ONE;
        List<BigInteger[]> residues = new ArrayList<>();
        Mac mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);


        List<BigInteger> factors = DiffieHellmanUtils.findSmallFactors(base.group().getTwistOrder());

        int n = factors.size();
        System.out.println(factors);

        for (int i = 0; i < n; i++) {
            BigInteger r = factors.get(i);
            if (r.equals(TWO))  continue;
            BigInteger h = base.group().findTwistGenerator(r);
            System.out.printf("Generator of order %d found: %d%n", r, h);
//            Challenge59ECDHBobResponse res = bob.initiate(base, order, h);
//            for (BigInteger b = ZERO; b.compareTo(r) < 0; b = b.add(ONE)) {  /* searching for Bob's secret key b modulo r */
//                mac.init(generateSymmetricKey(h, b, 32, MAC_ALGORITHM_NAME));
//                if (Arrays.equals(res.mac, mac.doFinal(res.msg.getBytes()))) {
//                    System.out.printf("Found b%d mod r%<d: %d, %d%n", residues.size(), b, r);
//                    residues.add(new BigInteger[]{b, r});
//                    prod = prod.multiply(r);
//                    if (prod.compareTo(order) > 0) {
//                        System.out.printf("Enough found%n\tQ: %d%n\tP: %d%n", order, prod);
//                        break ANOTHER_MODULUS;
//                    }
//                    break;
//                }
//            }
        }


        return null;//garnersAlgorithm(residues);
    }

    @SneakyThrows
    public static SecretKeySpec generateSymmetricKey(ECGroupElement A, BigInteger b, int len, String keyAlgorithm) {
        MessageDigest sha = MessageDigest.getInstance(len > 20  ?  "SHA-256" : "SHA-1");
        return  new SecretKeySpec(Arrays.copyOf(sha.digest(A.scale(b).toByteArray()), len), keyAlgorithm);
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

            BigInteger   privateKeyAlice = new DiffieHellmanHelper(group.getModulus(), q).generateExp().mod(q);
            ECDiffieHellman   ecBob = (ECDiffieHellman) Naming.lookup("rmi://localhost/ECDiffieHellmanBobService");
            Challenge59ECDHBobResponse  res = ecBob.initiate(base, q, base.scale(privateKeyAlice));
            Mac   mac = Mac.getInstance(MAC_ALGORITHM_NAME);
            SecretKey   macKey = generateSymmetricKey(res.B, privateKeyAlice, 32, MAC_ALGORITHM_NAME);
            mac.init(macKey);
            assert  Arrays.equals(mac.doFinal(res.msg.getBytes()), res.mac);
            System.out.println("DiffieHellman in the EC " + group + " works");

            b = breakChallenge59(base, q, "rmi://localhost/ECDiffieHellmanBobService");
            assert  ecBob.isValidPrivateKey(b) : "Bob's key not correct";
            System.out.printf("Recovered Bob's secret key: %x%n", b);

            System.out.println("\nChallenge 60");
            MontgomeryECGroup   mgroup = new MontgomeryECGroup(new BigInteger("233970423115425145524320034830162017933"),
                    valueOf(534), ONE, new BigInteger("233970423115425145498902418297807005944"));
            MontgomeryECGroup.ECGroupElement   mbase = mgroup.createPoint(
                    valueOf(4), new BigInteger("85518893674295321206118380980485522083"));

            assert  ZERO.equals(mbase.ladder(q));
            System.out.println("base^q = " + mbase.scale(q));
            System.out.println("base^q-1 = " + mbase.scale(q.subtract(ONE)));
            System.out.println("base^q-2 = " + mbase.scale(q.subtract(TWO)));
            System.out.println("base^q+1 = " + mbase.scale(q.add(ONE)));
            b = breakChallenge60(mbase, q, "rmi://localhost/ECDiffieHellmanBobService");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
