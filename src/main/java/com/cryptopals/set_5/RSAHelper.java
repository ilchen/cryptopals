package com.cryptopals.set_5;

import com.cryptopals.set_6.RSAHelperExt;
import lombok.Data;

import com.squareup.jnagmp.Gmp;
import lombok.SneakyThrows;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static com.cryptopals.Set5.isOdd;
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
        @SneakyThrows
        public boolean  verify(byte msg[], BigInteger signature) {
            byte[]  paddedMsg = encrypt(signature).toByteArray(),  hash;
            // BigInteger removed the most significant 0 from the padding
            if (paddedMsg[0] != 1)  return  false;
            int   i = 1;
            while (i < paddedMsg.length  &&  paddedMsg[i] == (byte) 0xff)  i++;
            if (paddedMsg[i++] != 0)  return  false;
            for (RSAHelperExt.HashMethod method : RSAHelperExt.HashMethod.values()) {
                if (paddedMsg.length - i > method.asn1.length
                        &&  Arrays.equals(method.asn1, Arrays.copyOfRange(paddedMsg, i, i + method.asn1.length))) {
                    MessageDigest md = MessageDigest.getInstance(method.name);
                    hash = md.digest(msg);
                    return  paddedMsg.length - i - method.asn1.length >= hash.length
                            &&  Arrays.equals(hash, Arrays.copyOfRange(paddedMsg,
                            i + method.asn1.length, i + method.asn1.length + hash.length));
                }
            }
            return  false;
        }
    }
    public static final BigInteger   PUBLIC_EXPONENT = BigInteger.valueOf(3L);
    private static final int         NUM_BITS = 1024;
    protected static final Random    SECURE_RANDOM = new SecureRandom(); // Thread safe

    protected final BigInteger    d,  n;
    private final PublicKey    pk;

    public RSAHelper() {
        this(PUBLIC_EXPONENT);
    }

    public RSAHelper(BigInteger e) {
        this(e, NUM_BITS);
    }

    /**
     * Constructs a new instance of RSA sk, pk pair. The modulus is guaranteed to be exactly {@code 2*numBits} long
     * @param e  the public exponent that will be used by the constructed instance
     * @param numBits  the number of bits in each of the {@code p} and {@code q} primes
     */
    public RSAHelper(BigInteger e, int numBits) {
        if (!isOdd(e) || e.compareTo(PUBLIC_EXPONENT) < 0) {
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

    public RSAHelper(BigInteger p, BigInteger q, BigInteger e) {
        BigInteger pOrd = p.subtract(ONE), qOrd = q.subtract(ONE);
        // Dividing by the GCD below results in a smaller private key.
        BigInteger et = pOrd.multiply(qOrd)/*.divide(pOrd.gcd(qOrd))*/;
        d = e.modInverse(et);
        n = p.multiply(q);
        pk = new PublicKey(e, n);
    }

    public PublicKey  getPublicKey() {
        return  pk;
    }

    public BigInteger  encrypt(BigInteger plainText) {
        return  pk.encrypt(plainText);
    }
}
