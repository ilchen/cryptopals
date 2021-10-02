package com.cryptopals;

import com.cryptopals.set_8.WeierstrassECGroup;
import com.cryptopals.set_9.DualECPRNG;
import com.fasterxml.jackson.databind.node.BigIntegerNode;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.cryptopals.Set8.NON_RESIDUE;
import static com.cryptopals.set_9.DualECPRNG.P;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;
import static java.util.stream.Collectors.*;

/**
 * Created by Andrei Ilchenko on 26-09-21.
 */
public class Set9 {
    public static final BigInteger
            CURVE_SECP256R1_PRIME = ONE.shiftLeft(256).subtract(ONE.shiftLeft(224)).add(ONE.shiftLeft(192)).add(ONE.shiftLeft(96)).subtract(ONE),
            CURVE_SECP256R1_ORDER = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
            CURVE_SECP256R1_B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);

    /**
     * Recovers the internal state of a curve P-256 based NIST Dual EC PRNG from a 32 bytes block produced
     * from an earlier invocation to it and from the knowledge of the exponent {@code d} such that {@code Q^d == P}
     * @param q  the Q point used to translate internal state of a Dual EC PRNG to its output
     * @param d  the exponent such that {@code Q^d == P}
     * @param fullBlock  a 32 random bytes produced by a Dual EC PRNG initialized with the Q point {@code q}
     * @return  candidates for the internal state of a Dual EC PRNG, typically only one.
     */
    static List<BigInteger>   breakChallenge70(WeierstrassECGroup.ECGroupElement q, BigInteger d, byte[] fullBlock) {
        assert  fullBlock.length == 32;
        // In ScreenOS, Dual EC is always used to generate 32 bytes of output at a time.
        // Get the first DUAL EC output block
        byte[]  block = Arrays.copyOf(fullBlock, DualECPRNG.MAX_BLOCK_BYTE_LENGTH);

        // Get the only two bytes of the second DUAL EC output block
        ByteBuffer   bb = ByteBuffer.wrap(Arrays.copyOfRange(fullBlock, DualECPRNG.MAX_BLOCK_BYTE_LENGTH, fullBlock.length));

        WeierstrassECGroup   secp256r1 = new WeierstrassECGroup(CURVE_SECP256R1_PRIME,
                CURVE_SECP256R1_PRIME.subtract(valueOf(3)), CURVE_SECP256R1_B, CURVE_SECP256R1_ORDER);
        // Produce candidates for the next internal state
        Stream<BigInteger>   nextStateCands = IntStream.range(0, 1 << 16).parallel().mapToObj(
                x -> {
                    // An extra byte to compensate for BigInteger taking an extra leading byte when the integer is >= 2^255
                    byte[]  extendedBlock = new byte[DualECPRNG.INTERNAL_STATE_BYTE_LENGTH + 1];
                    System.arraycopy(block, 0, extendedBlock,
                            extendedBlock.length - DualECPRNG.MAX_BLOCK_BYTE_LENGTH, DualECPRNG.MAX_BLOCK_BYTE_LENGTH);
                    extendedBlock[1] = (byte) (x >>> 8);
                    extendedBlock[2] = (byte) x;
                    return  new BigInteger(extendedBlock);
                })
                // Excluding those that don't represent x points on the secp256r1 curve.
                .filter(x -> !secp256r1.mapToY(x).equals(NON_RESIDUE))
                // And now computing the next internal state s
                .map(x -> secp256r1.createPoint(x, secp256r1.mapToY(x)).scale(d).getX());

        // Produce candidates for the first two bytes of the next block
        Map<ByteBuffer, List<BigInteger>>   nextBlockCands = nextStateCands.collect(groupingBy(s -> {
                    byte[]   nextBlock = q.scale(s).getX().toByteArray();
                    return  ByteBuffer.wrap(Arrays.copyOfRange(
                                nextBlock, nextBlock.length - DualECPRNG.MAX_BLOCK_BYTE_LENGTH,
                            nextBlock.length - DualECPRNG.MAX_BLOCK_BYTE_LENGTH + 2));
                }));
        return  nextBlockCands.get(bb);
    }

    public static void main(String[] args) {
        System.out.println("Challenge 70");

        // Generate a random exponent to arrive at a convenient Q
        BigInteger    e = new BigInteger(256, new SecureRandom()).mod(CURVE_SECP256R1_ORDER),
                      d = e.modInverse(CURVE_SECP256R1_ORDER);
        WeierstrassECGroup.ECGroupElement q = (WeierstrassECGroup.ECGroupElement) P.scale(e);
        Random rnd = new DualECPRNG(q);

        // In ScreenOS, Dual EC is always used to generate 32 bytes of output at a time.
        byte[]  fullBlock = new byte[32];
        rnd.nextBytes(fullBlock);
        List<BigInteger>   finalCandidates = breakChallenge70(q, d, fullBlock);
        for (BigInteger s : finalCandidates) {
            byte[]  seed = DualECPRNG.P.scale(s).getX().toByteArray();
            seed = Arrays.copyOfRange(seed, seed.length - DualECPRNG.INTERNAL_STATE_BYTE_LENGTH, seed.length);
            Random   deducedRnd = new DualECPRNG(seed, q);
            System.out.println("Trying internal state " + s);
            System.out.printf("Next integer from original PRNG:\t%d%nNext integer from deduced  PRNG:\t%d%n%n", rnd.nextInt(), deducedRnd.nextInt());
        }
    }
}
