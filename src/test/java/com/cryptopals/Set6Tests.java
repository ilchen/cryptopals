package com.cryptopals;

import com.cryptopals.set_6.DSAHelper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import com.cryptopals.set_6.RSAHelperExt;

import java.math.BigInteger;
import java.security.MessageDigest;

import static com.cryptopals.Set6.*;
import static com.cryptopals.set_6.DSAHelper.fromHash;
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

    @DisplayName("https://cryptopals.com/sets/6/challenges/43")
    @Test
    void  challenge43()  {
        assertAll("DSA basics",
                () -> {
                    DSAHelper   dsa = new DSAHelper();
                    DSAHelper.PublicKey   pk = dsa.getPublicKey();
                    DSAHelper.Signature   dsaSignature = dsa.sign(CHALLENGE_43_TEXT.getBytes());
                    assertTrue(pk.verifySignature(CHALLENGE_43_TEXT.getBytes(), dsaSignature),
                            "Signature doesn't verify");
                },
                () -> {
                    DSAHelper   dsa = new DSAHelper(DSAHelper.P, DSAHelper.Q, DSAHelper.G);
                    DSAHelper.PublicKey   pk = dsa.getPublicKey();
                    DSAHelper.Signature   dsaSignature = dsa.sign(CHALLENGE_43_TEXT.getBytes());
                    assertTrue(pk.verifySignature(CHALLENGE_43_TEXT.getBytes(), dsaSignature),
                            "Signature doesn't verify, standard P, Q, and G were used");
                },
                () -> {
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    BigInteger   h = fromHash(sha.digest(CHALLENGE_43_TEXT.getBytes()));
                    assertEquals("d2d0714f014a9784047eaeccf956520045c45265", h.toString(16),
                            "Wrong conversion of hash to a BigInteger");
                },
                () -> {
                    MessageDigest   sha = MessageDigest.getInstance("SHA-1");
                    DSAHelper.PublicKey   pk = new DSAHelper.PublicKey(DSAHelper.P, DSAHelper.Q, DSAHelper.G,
                            new BigInteger("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4" +
                                    "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004" +
                                    "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed" +
                                    "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b" +
                                    "bb283e6633451e535c45513b2d33c99ea17", 16));

                    BigInteger   x = breakChallenge43(CHALLENGE_43_TEXT.getBytes(), new DSAHelper.Signature(
                            new BigInteger("548099063082341131477253921760299949438196259240", 10),
                            new BigInteger("857042759984254168557880549501802188789837994940", 10)), pk);
                    assertEquals(new BigInteger("125489817134406768603130881762531825565433175625"), x,
                            "Wrong key found");
                    assertEquals("954edd5e0afe5542a4adf012611a91912a3ec16",
                            fromHash(sha.digest(x.toString(16).getBytes())).toString(16));
                });

    }
}
