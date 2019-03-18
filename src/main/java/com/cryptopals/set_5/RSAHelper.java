package com.cryptopals.set_5;

import lombok.Data;

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
    }
    public static final BigInteger   PUBLIC_EXPONENT = BigInteger.valueOf(3L);
    private static final int      NUM_BITS = 1024;
    private static final Random   SECURE_RANDOM = new SecureRandom(); // Thread safe

    private BigInteger   p,  q,  n,  e,  d;

    public RSAHelper() {
        this(PUBLIC_EXPONENT);
    }

    RSAHelper(BigInteger e) {
        if (e.mod(BigInteger.valueOf(2)).equals(ZERO) || e.compareTo(PUBLIC_EXPONENT) < 0) {
            throw  new IllegalArgumentException("Invalid public exponent: " + e);
        }
        while (true) {
            p = new BigInteger(NUM_BITS, 64, SECURE_RANDOM);
            q = new BigInteger(NUM_BITS, 64, SECURE_RANDOM);
            n = p.multiply(q);
            BigInteger pOrd = p.subtract(ONE), qOrd = q.subtract(ONE);
            BigInteger et = pOrd.multiply(qOrd).divide(pOrd.gcd(qOrd));
            try {
                d = e.modInverse(et);
                break;
            } catch (ArithmeticException ex) {
                // another try
            }
        }
        this.e = e;
    }

    public PublicKey  getPublicKey() {
        return  new PublicKey(e, n);
    }

    public BigInteger  encrypt(BigInteger plainText) {
        if (plainText.compareTo(n) >= 0)  throw  new IllegalArgumentException("Plain text too lager");
        return  plainText.modPow(e, n);
    }
}
