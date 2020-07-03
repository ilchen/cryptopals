package com.cryptopals.set_8;

import com.cryptopals.Set8;
import com.cryptopals.set_5.DiffieHellmanHelper;
import lombok.SneakyThrows;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.rmi.RemoteException;


public class ECDiffieHellmanBobService implements ECDiffieHellman {
    private ECGroup ecg;
    private ECGroupElement   g;
    private SecretKeySpec macKey;
    private BigInteger  privateKey;
    private final Mac mac;

    @SneakyThrows
    public ECDiffieHellmanBobService() {
        mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);
    }

    private void  init(ECGroupElement g, BigInteger q) {
        if (ecg == null  ||  !ecg.equals(g.group())  ||  !this.g.equals(g)) {
            ecg = g.group();
            this.g = g;
            DiffieHellmanHelper   dhh = new DiffieHellmanHelper(ecg.getModulus(), q);
            BigInteger   pk;
            do {     /* Ensure the private key has the maximum possible number of bits */
                pk = dhh.generateExp().mod(q);
            }  while (pk.bitLength() != q.bitLength());
            privateKey = pk;
        }
    }

    @Override
    @SneakyThrows
    public Set8.Challenge59ECDHBobResponse initiate(ECGroupElement g, BigInteger q, ECGroupElement A) {
        // A bit contrived for Bob to hang on to the same private key across new sessions, however this is what
        // Challenge 59 calls for.
        init(g, q);

        macKey = Set8.generateSymmetricKey(A, privateKey, 32, Set8.MAC_ALGORITHM_NAME);
        mac.init(macKey);

        return  new Set8.Challenge59ECDHBobResponse(
                g.scale(privateKey), Set8.CHALLENGE56_MSG, mac.doFinal(Set8.CHALLENGE56_MSG.getBytes()) );
    }

    @Override
    @SneakyThrows
    public Set8.Challenge60ECDHBobResponse initiate(ECGroupElement g, BigInteger q, BigInteger xA) {
        // A bit contrived for Bob to hang on to the same private key across new sessions, however this is what
        // Challenge 60 calls for.
        init(g, q);

        System.out.printf("b mod 11 = %d%n", privateKey.mod(BigInteger.valueOf(11)));
        System.out.printf("b mod 107 = %d%n", privateKey.mod(BigInteger.valueOf(107)));
        System.out.printf("b mod 197 = %d%n", privateKey.mod(BigInteger.valueOf(197)));
        System.out.printf("b mod 1621 = %d%n", privateKey.mod(BigInteger.valueOf(1621)));
        System.out.printf("b mod 105143 = %d%n", privateKey.mod(BigInteger.valueOf(105143)));
        System.out.printf("b mod 405373 = %d%n", privateKey.mod(BigInteger.valueOf(405373)));
        System.out.printf("b mod 2323367 = %d%n", privateKey.mod(BigInteger.valueOf(2323367)));
        System.out.printf("b mod 1177 = %d%n", privateKey.mod(BigInteger.valueOf(1177)));
        System.out.printf("b mod 21079 = %d%n", privateKey.mod(BigInteger.valueOf(21079)));
        macKey = Set8.generateSymmetricKey(g.group(), xA, privateKey, 32, Set8.MAC_ALGORITHM_NAME);
        System.out.printf("%d^b = %d%n", xA, g.group().ladder(xA, privateKey));
        mac.init(macKey);
        return  new Set8.Challenge60ECDHBobResponse(g.ladder(privateKey), Set8.CHALLENGE56_MSG,
                mac.doFinal(Set8.CHALLENGE56_MSG.getBytes()) );
    }

    @Override
    public boolean isValidPrivateKey(BigInteger b) {
        boolean  res = false;
        if (ecg != null) {
            res = b.equals(privateKey);
            // Allow only one test before regenerating the private key.
//          For Challenge 60 we need to test for multiple combinations of Bob's private keys
//            ecg = null;
//            privateKey = null;
        }
        return  res;
    }
}
