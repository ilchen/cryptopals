package com.cryptopals.set_9;

import com.cryptopals.set_8.WeierstrassECGroup;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static com.cryptopals.Set9.*;
import static java.math.BigInteger.valueOf;

/**
 * Implements the Dual EC PRNG algorithm as defined in <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-90r.pdf">NIST Special Publication 800-90 Revised</a>.
 * This implementation caters to the case where the required security strength is 128 bits and therefore NIST curve P-256
 * is used. Given the compatibility with the interface of {@link Random}, this implementation doesn't support
 * additional input that Duel EC PRNG regards as optional.
 */
public class DualECPRNG extends Random {
    public static final int   INTERNAL_STATE_BYTE_LENGTH = 32,  MAX_BLOCK_BYTE_LENGTH = 30;
    // Standard NIST P-256 (aka secp256r) curve
    private static final WeierstrassECGroup   secp256r1 = new WeierstrassECGroup(CURVE_SECP256R1_PRIME,
            CURVE_SECP256R1_PRIME.subtract(valueOf(3)), CURVE_SECP256R1_B, CURVE_SECP256R1_ORDER);

    // This point P also happens to be NIST's canonical generator for P-256.
    public static final WeierstrassECGroup.ECGroupElement   P = secp256r1.createPoint(
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16));
    // NIST's recommended Q
    public static final WeierstrassECGroup.ECGroupElement   NIST_Q = secp256r1.createPoint(
            new BigInteger("c97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192", 16),
            new BigInteger("b28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046", 16));;
    private BigInteger   s;
    private long   blockCounter;
    private final WeierstrassECGroup.ECGroupElement  Q;


    /**
     * Initializes this PRNG using user-supplied values.
     * @param seed  a 32-byte long seed value for the generator
     * @param q  a {@link com.cryptopals.set_8.WeierstrassECGroup.ECGroupElement} point that the generator will
     *           use for mapping its internal state {@link DualECPRNG#s} to the next block of random output.
     */
    public DualECPRNG(byte[] seed, WeierstrassECGroup.ECGroupElement q) {
        if (seed.length != INTERNAL_STATE_BYTE_LENGTH)  throw  new IllegalArgumentException("Seed is not 32 bytes long");
        if (q.equals(P))  throw  new IllegalArgumentException(String.format("Supplied Q point %s is the same as P", q));

        // Prepends an extra zero-byte to care of two's complement binary representation used by BigInteger
        byte  appendedSeed[] = new byte[INTERNAL_STATE_BYTE_LENGTH + 1];
        System.arraycopy(seed, 0, appendedSeed, 1, INTERNAL_STATE_BYTE_LENGTH);
        s = new BigInteger(appendedSeed);
        Q = q; // WeierstrassECGroup.ECGroupElement is an immutable class
    }

    public DualECPRNG(byte[] seed) {
        this(seed, NIST_Q);
    }

    public DualECPRNG(WeierstrassECGroup.ECGroupElement q) {
        s = new BigInteger(getRandomBytesForBigInteger(32));
        Q = q;
    }

    public DualECPRNG() {
        s = new BigInteger(getRandomBytesForBigInteger(32));
        Q = NIST_Q;
    }

    /**
     * Reinitializes this PRNG. Should be invoked after generating 2^32 blocks of PRNG output.
     */
    private void  reseed() {
        synchronized (Q) {
            this.s = new BigInteger(getRandomBytesForBigInteger(32));
            blockCounter = 0;
        }
    }

    /**
     * Prepends an extra zero-byte to care of two's complement binary representation assumed by BigInteger. Otherwise
     * some numbers will end up negative.
     */
    private static byte[]  getRandomBytesForBigInteger(int nBytes) {
        byte   s[] = new byte[nBytes+1];
        new SecureRandom().nextBytes(s); // On Linux or MacOS will use Fortuna to seed
        s[0] = 0;
        return  s;
    }

    @Override
    protected int  next(int bits) {
        int   r;
        synchronized (Q) {
            if (++blockCounter > 1L << Integer.SIZE) {
                reseed();
            }
            s = P.scale(s).getX();
            // Taking the 240 least significant bits, and then 32 most significant ones
            byte[]  tmp = Q.scale(s).getX().toByteArray();
            tmp = Arrays.copyOfRange(tmp, tmp.length - MAX_BLOCK_BYTE_LENGTH, tmp.length - MAX_BLOCK_BYTE_LENGTH + Integer.BYTES);
            r = ByteBuffer.wrap(tmp).getInt();
            s = P.scale(s).getX();
        }
        return  r >>> Integer.SIZE - bits;
    }

    @Override
    public void  nextBytes(byte[] bytes) {
        synchronized (Q) {
            if (blockCounter + bytes.length / MAX_BLOCK_BYTE_LENGTH
                             + (bytes.length % MAX_BLOCK_BYTE_LENGTH > 0  ?  1 : 0) > 1L << Integer.SIZE) {
                reseed();
            }
            int  numBytesRemaining = bytes.length,  numBytesToCopy;
            byte[]   r;
            do {
                blockCounter++;
                s = P.scale(s).getX();
                r = Q.scale(s).getX().toByteArray();

                numBytesToCopy = Math.min(MAX_BLOCK_BYTE_LENGTH, numBytesRemaining);
                // Copying the least significant MAX_BLOCK_BYTE_LENGTH bytes,
                // and then taking numBytesRemaining most significant bytes
                System.arraycopy(r, r.length - MAX_BLOCK_BYTE_LENGTH,
                        bytes, bytes.length - numBytesRemaining, numBytesToCopy);
                numBytesRemaining -= numBytesToCopy;
            } while (numBytesRemaining > 0);
            s = P.scale(s).getX();
        }
    }

}
