package com.cryptopals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import com.cryptopals.set_6.RSAHelperExt;

import java.math.BigInteger;

import static com.cryptopals.Set6.PLAIN_TEXT;
import static com.cryptopals.Set6.forgeSignature;
import static org.junit.jupiter.api.Assertions.*;

public class Set6Tests {
    @DisplayName("https://cryptopals.com/sets/6/challenges/41")
    @Test
    void  challenge41()  {
        RSAHelperExt rsa = new RSAHelperExt(BigInteger.valueOf(17));
        BigInteger     cipherTxt = rsa.encrypt(new BigInteger(PLAIN_TEXT.getBytes()));
        rsa.decrypt(cipherTxt);   // Only one decryption allowed
        assertEquals(BigInteger.ZERO, rsa.decrypt(cipherTxt));
        assertArrayEquals(PLAIN_TEXT.getBytes(),
                          Set6.breakChallenge41(cipherTxt, rsa.getPublicKey(), rsa::decrypt).toByteArray());
    }

    @DisplayName("https://cryptopals.com/sets/6/challenges/42")
    @Test
    void  challenge42()  {
        byte   msg[] = "hi mom".getBytes();
        RSAHelperExt   rsa = new RSAHelperExt(BigInteger.valueOf(3));
        BigInteger   signature = rsa.sign(msg, RSAHelperExt.HashMethod.SHA1);
        assertTrue(rsa.verify(msg, signature), "Valid signature didn't verify");
        assertTrue(rsa.verify(msg, forgeSignature(msg, rsa.getPublicKey(), RSAHelperExt.HashMethod.SHA1)),
                "Forged signature didn't verify");
    }
}
