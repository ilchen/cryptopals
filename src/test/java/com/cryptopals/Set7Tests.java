package com.cryptopals;

import com.cryptopals.set_7.MDHelper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.cryptopals.Set7.*;
import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.xml.bind.DatatypeConverter;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

class Set7Tests {

    @DisplayName("https://cryptopals.com/sets/7/challenges/49")
    @Test
    /** The corresponding SpringBoot server application must be running. */
    void  challenge49() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Set7   encryptor = new Set7(Cipher.ENCRYPT_MODE, Set1.YELLOW_SUBMARINE_SK);
        assertAll("Two parts of Challenge 49",
                () -> {
                    String  macedMsg = encryptor.generateCreditTransferMsg(
                            "DE92500105173721848769", BigDecimal.valueOf(100));
                    assertEquals(202, encryptor.submitMACedMessage(CHALLENGE49_SCT_TARGET, macedMsg));
                    assertEquals(202, encryptor.submitMACedMessage(CHALLENGE49_SCT_TARGET,
                            Set7.breakChallenge49(macedMsg, "from=id100000013",
                                                  encryptor.getBase64BlockLen())));
                    assertEquals(401, encryptor.submitMACedMessage(CHALLENGE49_SCT_TARGET,
                            Set7.breakChallenge49(macedMsg, "from=id100000013",
                                    encryptor.getBase64BlockLen()) + "extraneous+suffix"));
                },
                () -> {
                    String  macedMsg = encryptor.generateMultipleCreditTransferMsg(
                            new String[] { "NL35ABNA7925653426", "PT61003506835911954593562"},
                            new BigDecimal[] {   BigDecimal.valueOf(101),  BigDecimal.valueOf(102)});
                    assertEquals(202, encryptor.submitMACedMessageURLEncoded(CHALLENGE49_MCT_TARGET, macedMsg));

                    String   attackersMacedMsg = encryptor.generateMultipleCreditTransferMsg(
                            new String[] { "RO63EEOM5869471527249753"},
                            new BigDecimal[] {   BigDecimal.valueOf(10043041)   }),
                            forgedMacedMsg = Set7.breakChallenge49Mct(macedMsg, attackersMacedMsg,
                                    encryptor.cipher.getBlockSize(), encryptor.getBase64BlockLen());
                    assertEquals(202,
                            encryptor.submitMACedMessageURLEncoded(CHALLENGE49_MCT_TARGET, forgedMacedMsg));
                    assertEquals(401,
                            encryptor.submitMACedMessageURLEncoded(CHALLENGE49_MCT_TARGET,
                                    forgedMacedMsg + '+'));
                });
    }

    @DisplayName("https://cryptopals.com/sets/7/challenges/50")
    @Test
    void  challenge50() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, ScriptException {
        Set7   encryptor = new Set7(Cipher.ENCRYPT_MODE, Set1.YELLOW_SUBMARINE_SK);
        byte[]  trgtMac = encryptor.generateCbcMac(CHALLENGE50_TEXT.getBytes(), encryptor.zeroedIV),
                mac = encryptor.generateCbcMac(CHALLENGE50_TARGET_TEXT.getBytes(), encryptor.zeroedIV);
        assertEquals("296b8d7cb78a243dda4d0a61d33bbdd1", DatatypeConverter.printHexBinary(trgtMac).toLowerCase());
        String  attackersMacedMsg = breakChallenge50(CHALLENGE50_TEXT.getBytes(), mac,
                    CHALLENGE50_TARGET_TEXT.getBytes(), encryptor.cipher.getBlockSize());
        mac = encryptor.generateCbcMac(attackersMacedMsg.getBytes(StandardCharsets.ISO_8859_1), encryptor.zeroedIV);
        assertArrayEquals(trgtMac, mac);
        assertDoesNotThrow(() -> {
            ScriptEngineManager  manager = new ScriptEngineManager();
            ScriptEngine  engine = manager.getEngineByName("JavaScript");
            engine.eval(attackersMacedMsg);
        });
    }

    @DisplayName("https://cryptopals.com/sets/7/challenges/52")
    @Test
    void  challenge52() throws NoSuchAlgorithmException, NoSuchPaddingException,
            BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        MDHelper   mdHelper = new MDHelper(new byte[] { 0, 1 }, new byte[] { 0, 1, 2 }, "Blowfish", 8);
        byte   collision[][] = mdHelper.findCollision();
        if (collision != null) {
            assertFalse(Arrays.equals(collision[0], collision[1]));
            assertArrayEquals(mdHelper.mdHard(collision[0]), mdHelper.mdHard(collision[1]));
        } else {
            fail("No collisions found");
        }
    }

    @DisplayName("https://cryptopals.com/sets/7/challenges/53")
    @Test
    void  challenge53() throws NoSuchAlgorithmException, NoSuchPaddingException,
            BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        byte[]   H = { 0, 1 },  H2 = { 0, 1, 2 };
        MDHelper   mdHelper = new MDHelper(H, H2, "Blowfish", 8);
        byte   collision[][] = mdHelper.findCollision(4);

        assertNotNull(collision, "No collision found");
        assertArrayEquals(
                mdHelper.mdInnerLast(collision[0], H, 0, 1),
                mdHelper.mdInnerLast(collision[1], H, 0, 9));

        byte   longMsg[] = new byte[Long.BYTES * 0x10000];
        new SecureRandom().nextBytes(longMsg);
        byte   secondPreimage[] = mdHelper.find2ndPreimage(longMsg);
        assertFalse(Arrays.equals(longMsg, secondPreimage));
        assertArrayEquals(mdHelper.mdEasy(longMsg), mdHelper.mdEasy(secondPreimage));
    }
}
