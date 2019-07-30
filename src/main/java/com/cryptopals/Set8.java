package com.cryptopals;

import com.cryptopals.set_5.DiffieHellmanHelper;
import com.cryptopals.set_8.DiffieHellman;
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

import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.ONE;

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
        DiffieHellmanHelper  dh = new DiffieHellmanHelper(P, G);
        List<BigInteger>   factors = dh.findSmallFactors(Q);
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

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
