package com.cryptopals.set_8;

import com.cryptopals.Set8;
import lombok.SneakyThrows;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.rmi.RemoteException;

import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.ONE;

public class  DiffieHellmanBobService implements DiffieHellman {
    private DiffieHellmanHelperExt   df;
    private SecretKeySpec   macKey;
    private BigInteger  privateKey;
    private final Mac   mac;

    @SneakyThrows
    public DiffieHellmanBobService() {
        mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);
    }

    @Override
    @SneakyThrows
    synchronized public Set8.Challenge57DHBobResponse initiate(BigInteger p, BigInteger g, BigInteger q, BigInteger A) {
        // Best practices for DH as recommended in Cryptography Engineering, 2nd edition:
        // Are p and q primes? Does q divide p-1? Is g different from 1? Is g^q equal 1?
        if (!p.isProbablePrime(8)  ||  !q.isProbablePrime(8)
                ||  !p.subtract(ONE).remainder(q).equals(ZERO)
                ||  g.equals(ONE)  ||  !g.modPow(q, p).equals(ONE)) {
            throw  new RemoteException("Invalid arguments");
        }

        // A bit contrived for Bob to hang on to the same private key across new sessions, however this is what
        // Challenge 57 calls for.
        if (df == null  ||  !p.equals(df.getModulus())  ||  !g.equals(df.getGenerator())) {
            df = new DiffieHellmanHelperExt(p, g, q);
            privateKey = df.generateExp();
        }
        macKey = df.generateSymmetricKey(A, privateKey, 32, Set8.MAC_ALGORITHM_NAME);
        mac.init(macKey);
        return  new Set8.Challenge57DHBobResponse(g.modPow(privateKey, df.getModulus()), Set8.CHALLENGE56_MSG,
                                                  mac.doFinal(Set8.CHALLENGE56_MSG.getBytes()) );
    }

    @Override
    synchronized public boolean  isValidPrivateKey(BigInteger b) {
        boolean  res = false;
        if (df != null) {
            res = b.equals(privateKey);
            // Allow only one test before regenerating the private key.
            df = null;
            privateKey = null;
        }
        return  res;
    }
}
