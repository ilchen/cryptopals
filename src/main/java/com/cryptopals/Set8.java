package com.cryptopals;

import com.cryptopals.set_5.DiffieHellmanHelper;
import com.cryptopals.set_8.DiffieHellman;
import com.cryptopals.set_8.DiffieHellmanHelperExt;
import lombok.Data;

import javax.crypto.Mac;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.math.BigInteger.*;

/**
 * Created by Andrei Ilchenko on 28-07-19.
 */
public class Set8 {
    public static final String   CHALLENGE56_MSG = "crazy flamboyant for the rap enjoyment";
    public static final String   MAC_ALGORITHM_NAME = "HmacSHA256";
    static final BigInteger   P = new BigInteger(
            "7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475"
            + "480089726140708102474957429903531369589969318716771"),
                              G = new BigInteger(
             "45653563970957406554368545034838268321361061416395634877324381953436904376061178"
             + "28318042418238184896212352329118608100083187535033402010599512641674644143"),
                              Q = new BigInteger("236234353446506858198510045061214171961");

    @Data
    public static class Challenge57DHBobResponse implements Serializable {
        final BigInteger B;
        final String   msg;
        final byte[]   mac;
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
            b = dh.dlog(y, BigInteger.valueOf(2).pow(20), DiffieHellmanHelper::f);
            System.out.printf("Recovered dlog of %d:%n %d%n", y, b);
            assert  dh.getGenerator().modPow(b, dh.getModulus()).equals(y);

//            y = new BigInteger("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733");
//            b = dh.dlog(y, BigInteger.valueOf(2).pow(40), DiffieHellmanHelper::f);
//            System.out.printf("Recovered dlog of %d:%n %d%n", y, b);
//            assert  dh.getGenerator().modPow(b, dh.getModulus()).equals(y);

            b = breakChallenge58("rmi://localhost/DiffieHellmanBobService");
            assert  bob.isValidPrivateKey(b) : "Bob's key not correct";
            System.out.printf("Recovered Bob's secret key: %x%n", b);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
