package com.cryptopals.set_8;

import com.cryptopals.set_6.DSAHelper;

import java.math.BigDecimal;
import java.math.BigInteger;

import static com.cryptopals.set_6.DSAHelper.hashAsBigInteger;

/**
 * A broken implementation of ECDSA that produces biased {@code k} numbers for each signature. The bias is that
 * {@code k}'s least significant 8 bits are zeros.s
 */
public class BiasedECDSA extends ECDSA {
    public BiasedECDSA(ECGroupElement g, BigInteger order) {
        super(g, order);
    }

    @Override
    public DSAHelper.Signature sign(byte[] msg) {
        // k is biased in having the 8 least significant bits as zeros
        BigInteger   k = DSAHelper.generateK(n).shiftRight(8).shiftLeft(8),  r = G.scale(k).getX();
        return  new DSAHelper.Signature(r, k.modInverse(n).multiply(hashAsBigInteger(msg).add(d.multiply(r))).mod(n));
    }

    public BigInteger  getPrivateKey() {
        return  d;
    }
}
