package com.cryptopals.set_8;

import com.cryptopals.set_6.DSAHelper;
import static com.cryptopals.set_6.DSAHelper.hashAsBigInteger;

import lombok.Data;

import java.math.BigInteger;

/**
 * This class implements ECDSA atop of an elliptic curve group in either the Montgomery or the Weierstrass form.
 *
 * Created by Andrei Ilchenko on 12-10-19.
 */
public class ECDSA {
    @Data
    public static class PublicKey {
        private final ECGroupElement   G;
        private final BigInteger       n;
        private final ECGroupElement   Q;

        public boolean  verifySignature(byte msg[], DSAHelper.Signature signature) {
            BigInteger   w = signature.getS().modInverse(n),  u1 = hashAsBigInteger(msg).multiply(w).mod(n),
                    u2 = signature.getR().multiply(w).mod(n);
            return  G.scale(u1).combine(Q.scale(u2)).getX().equals(signature.getR());
        }
    }

    private final ECGroupElement   G;

    // n is the order of group E(Fp), d is the private key
    private final BigInteger   n,  d;


    /**
     * Constructs an ECDSA sk/pk pair
     * @param g  a generator of a cyclic elliptic curve group
     * @param order  the order of the generator
     */
    public ECDSA(ECGroupElement g, BigInteger order) {
        G = g;     n = order;
        d = DSAHelper.generateK(n);
    }

    /**
     * Constructs an ECDSA sk/pk pair
     * @param g  a generator of a cyclic elliptic curve group
     * @param order  the order of the generator
     */
    public ECDSA(ECGroupElement g, BigInteger order, BigInteger d) {
        G = g;     n = order;
        this.d = d;
    }

    public PublicKey getPublicKey() {
        return  new PublicKey(G, n, G.scale(d));
    }

    public DSAHelper.Signature sign(byte msg[]) {
        BigInteger   k = DSAHelper.generateK(n),  r = G.scale(k).getX();
        return  new DSAHelper.Signature(r, k.modInverse(n).multiply(hashAsBigInteger(msg).add(d.multiply(r))).mod(n));
    }
}
