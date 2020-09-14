package com.cryptopals;

import com.cryptopals.set_9.RainbowTable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import sun.security.provider.MD4;


import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static com.cryptopals.set_9.RainbowTable.getPlainText;
import static com.cryptopals.set_9.RainbowTable.isAscii3295;
import static org.junit.jupiter.api.Assertions.*;

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

}
