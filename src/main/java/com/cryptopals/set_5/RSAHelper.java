package com.cryptopals.set_5;

import lombok.Data;

import com.squareup.jnagmp.Gmp;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.ONE;

/**
 * Created by Andrei Ilchenko on 18-03-19.
 */
public class RSAHelper {
    @Data
    public static class PublicKey {
        final BigInteger  e,  modulus;
        public BigInteger  encrypt(BigInteger plainText) {
            if (plainText.compareTo(modulus) >= 0)  throw  new IllegalArgumentException("Plain text too large");
            return  Gmp.modPowInsecure(plainText, e, modulus);
        }
    }
    public static final BigInteger   PUBLIC_EXPONENT = BigInteger.valueOf(3L);
    private static final int      NUM_BITS = 1024;
    protected static final Random   SECURE_RANDOM = new SecureRandom(); // Thread safe

    protected final BigInteger    d,  n;
    private final PublicKey    pk;

    public RSAHelper() {
        this(PUBLIC_EXPONENT);
    }

    public RSAHelper(BigInteger e) {
        this(e, NUM_BITS);
    }

    public RSAHelper(BigInteger e, int numBits) {
        if (e.mod(BigInteger.valueOf(2)).equals(ZERO) || e.compareTo(PUBLIC_EXPONENT) < 0) {
            throw  new IllegalArgumentException("Invalid public exponent: " + e);
        }
        if (numBits < 64/*  ||  ((numBits & numBits - 1) != 0)*/) {
            throw  new IllegalArgumentException("Number of bits in modulus is not a power of 2: " + numBits);
        }
        BigInteger   _p,  _q,  _n,  _d;
        while (true) {
            _p = BigInteger.probablePrime(numBits, SECURE_RANDOM);
            _q = BigInteger.probablePrime(numBits, SECURE_RANDOM);
            _n = _p.multiply(_q);
            if (_n.bitLength() != 2 * numBits)  continue;
            BigInteger pOrd = _p.subtract(ONE), qOrd = _q.subtract(ONE);
            // Dividing by the GCD below results in a smaller private key.
            BigInteger et = pOrd.multiply(qOrd)/*.divide(pOrd.gcd(qOrd))*/;
            try {
                _d = e.modInverse(et);
                break;
            } catch (ArithmeticException ex) {
                // another try
            }
        }
        n = _n;     d = _d;
        pk = new PublicKey(e, n);
    }

    public PublicKey  getPublicKey() {
        return  pk;
    }

    public BigInteger  encrypt(BigInteger plainText) {
        return  pk.encrypt(plainText);
    }
}
