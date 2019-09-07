package com.cryptopals.set_8;

import com.cryptopals.Set8;
import com.cryptopals.set_5.DiffieHellmanHelper;
import lombok.SneakyThrows;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.rmi.RemoteException;


public class ECDiffieHellmanBobService implements ECDiffieHellman {
    private ECGroup   ecg;
    private ECGroup.ECGroupElement   g;
    private SecretKeySpec macKey;
    private BigInteger  privateKey;
    private final Mac mac;

    @SneakyThrows
    public ECDiffieHellmanBobService() {
        mac = Mac.getInstance(Set8.MAC_ALGORITHM_NAME);
    }

    @Override
    @SneakyThrows
    public Set8.Challenge59ECDHBobResponse initiate(ECGroup.ECGroupElement g, BigInteger q, ECGroup.ECGroupElement A) throws RemoteException {
        // A bit contrived for Bob to hang on to the same private key across new sessions, however this is what
        // Challenge 59 calls for.
        if (ecg == null  ||  !ecg.equals(g.group())  ||  !this.g.equals(g)) {
            ecg = g.group();
            this.g = g;
            privateKey = new DiffieHellmanHelper(ecg.getModulus(), q).generateExp().mod(q);
        }

        macKey = Set8.generateSymmetricKey(A, privateKey, 32, Set8.MAC_ALGORITHM_NAME);
        mac.init(macKey);
        return  new Set8.Challenge59ECDHBobResponse(g.scale(privateKey), Set8.CHALLENGE56_MSG,
                mac.doFinal(Set8.CHALLENGE56_MSG.getBytes()) );
    }

    @Override
    public boolean isValidPrivateKey(BigInteger b) throws RemoteException {
        boolean  res = false;
        if (ecg != null) {
            res = b.equals(privateKey);
            // Allow only one test before regenerating the private key.
            ecg = null;
            privateKey = null;
        }
        return  res;
    }
}
