package com.cryptopals;

import com.cryptopals.set_8.WeierstrassECGroup;
import com.cryptopals.set_9.DualECPRNG;
import com.cryptopals.set_9.RainbowTable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import sun.security.provider.MD4;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

import static com.cryptopals.Set9.CURVE_SECP256R1_ORDER;
import static com.cryptopals.set_9.DualECPRNG.P;
import static com.cryptopals.set_9.RainbowTable.getPlainText;
import static com.cryptopals.set_9.RainbowTable.isAscii3295;
import static java.util.stream.Collectors.counting;
import static org.junit.jupiter.api.Assertions.*;
import static java.util.stream.Collectors.groupingBy;

class Set9Tests {

    @DisplayName("Challenge 67")
    @ParameterizedTest
    @ValueSource(ints = { 4, 5 })
    void  challenge67(int numChars) throws NoSuchAlgorithmException, InvalidKeyException {
        RainbowTable rainbowTable = new RainbowTable(numChars, "MD4");
        MessageDigest   md4 = MD4.getInstance();
        Random   rnd = new SecureRandom();

        // The probability of a rainbow table containing a preimage is approximately 0.63
        int   cnt = 0,  totalTries = 1000,  expectedCount = (int) (totalTries * .61);

        for (int i=0; i < 32; i++) { /* Check the working of the PRF */
            byte[]   p = getPlainText(numChars, rnd),  p1 = rainbowTable.fi(i, md4, p);
            assertEquals(p.length, p1.length);
            assertTrue(isAscii3295(p));
            assertTrue(isAscii3295(p1));
            System.out.printf("%s -> %s%n", new String(p), new String(p1));
        }

        for (int i=0; i < totalTries; i++) {
            byte[]   pw = getPlainText(numChars, rnd),  hash = md4.digest(pw),
                     crackedPw = rainbowTable.crackPassword(hash);
            System.out.printf("%s hashes into: %s. ", new String(pw), DatatypeConverter.printHexBinary(hash));
            System.out.printf("Recovering the original password from the hash with the rainbow table yields: %s%n",
                    crackedPw == null  ?  "null" : new String(crackedPw));
            if (Arrays.equals(pw, crackedPw))  cnt++;
        }

        System.out.printf("Of %d password hashes %d were inverted successfully%n", totalTries, cnt);
        assertTrue(cnt >= expectedCount, "Expected frequency of 0.63 for inverting is not met");
    }

    @DisplayName("Chi-squared test of DUAL EC DRBG")
    @ParameterizedTest
    @ValueSource(ints = { 3000 })
    void  dualEcDrbgChiSquared(int numExperiments) {
        Random   rnd = new DualECPRNG();
        int     numCategories = 51;
        double  p95 = 67.5; // for 50 degrees of freedom
        Map<Integer, Long> histogram = rnd.ints(0, numCategories).limit(numExperiments).boxed()
                .collect(groupingBy(Function.identity(), counting()));
        System.out.println(histogram);

        double   chiSquared = 0.,  p = 1. / numCategories;
        for (int category=0; category < numCategories; category++) {
            long   y = histogram.getOrDefault(category, 0L);
            chiSquared += y * y / p;
        }
        chiSquared = chiSquared / numExperiments - numExperiments;
        System.out.printf("Degrees of freedom (\u03BD)=%d, \u03C7^2=%.2f%n", numCategories-1, chiSquared);

        assertTrue(chiSquared < p95,
                "The likelyhood of getting such a run with a true uniform PRNG is less than 5%");
    }

    @DisplayName("Challenge 70")
    @Test
    void  challenge70()  {
        // Generate a random exponent to arrive at a convenient Q
        BigInteger e = new BigInteger(256, new SecureRandom()).mod(CURVE_SECP256R1_ORDER),
                   d = e.modInverse(CURVE_SECP256R1_ORDER);
        WeierstrassECGroup.ECGroupElement q = (WeierstrassECGroup.ECGroupElement) P.scale(e);
        Random rnd = new DualECPRNG(q);

        // In ScreenOS, Dual EC is always used to generate 32 bytes of output at a time.
        byte[]  fullBlock = new byte[32];
        rnd.nextBytes(fullBlock);
        List<BigInteger> finalCandidates = Set9.breakChallenge70(q, d, fullBlock);
        boolean   internalStateFound = false;
        for (BigInteger s : finalCandidates) {
            byte[]  seed = DualECPRNG.P.scale(s).getX().toByteArray();
            seed = Arrays.copyOfRange(seed, seed.length - DualECPRNG.INTERNAL_STATE_BYTE_LENGTH, seed.length);
            Random   deducedRnd = new DualECPRNG(seed, q);
            int   nextOrg = rnd.nextInt(),  nextDeduced = deducedRnd.nextInt();
            System.out.println("Trying internal state " + s);
            System.out.printf("Next integer from original PRNG:\t%d%nNext integer from deduced  PRNG:\t%d%n%n", nextOrg, nextDeduced);
            internalStateFound |= nextDeduced == nextOrg;
        }
        assertTrue(internalStateFound);
    }
}
