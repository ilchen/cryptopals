package com.cryptopals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Test cases for Cryptopals Set 1 challenges")
class Set1Tests {

    @Test @DisplayName("https://cryptopals.com/sets/1/challenges/1")
    void  challenge1() {
        assertEquals("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
                Set1.challenge1(
                        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
                "Base64 encoding broken");
    }

    @Test @DisplayName("https://cryptopals.com/sets/1/challenges/2")
    void  challenge2() {
        String   hex1 = "1c0111001f010100061a024b53535009181c";
        String   hex2 = "686974207468652062756c6c277320657965";

        assertEquals("746865206b696420646f6e277420706c6179",
                DatatypeConverter.printHexBinary(
                        Set1.challenge2(DatatypeConverter.parseHexBinary(hex1),
                                DatatypeConverter.parseHexBinary(hex2))).toLowerCase());
    }

    @Test @DisplayName("https://cryptopals.com/sets/1/challenges/3")
    void  challenge3() {
        Set1.FrequencyAnalysisHelper res = Set1.challenge3Helper(DatatypeConverter.parseHexBinary(
                "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));
        assertAll("deciphered",
                () -> assertEquals('X', res.getKey()),
                () -> assertEquals("Cooking MC's like a pound of bacon",
                        new String(res.getPossiblePlainText())));
    }

    @Test @DisplayName("https://cryptopals.com/sets/1/challenges/4")
    void  challenge4() throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource("challenge4.txt")).getFile());
        List<Set1.FrequencyAnalysisReportingHelper> cands = Set1.challenge4(file.toURI().toURL().toString());
        assertAll("Candidates",
                () -> {
                    assertEquals(1, cands.size());
                    Set1.FrequencyAnalysisReportingHelper cand = cands.get(0);

                    assertAll("found most likely candidate",
                            () -> assertEquals(cand.getLine(), 170),
                            () -> assertEquals("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f",
                                    cand.getCipherText()),
                            () -> assertEquals(2.03479f, cand.getCandInfo().getScore()),
                            () -> assertEquals('5', cand.getCandInfo().getKey()),
                            () -> assertEquals("Now that the party is jumping\n",
                                    new String(cand.getCandInfo().getPossiblePlainText())));
                }
        );
    }

    @Test @DisplayName("https://cryptopals.com/sets/1/challenges/5")
    void  challenge5() {
        String   plainText = "Burning 'em, if you ain't quick and nimble\n" + "I go crazy when I hear a cymbal",
                 key = "ICE";
        assertEquals("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
                "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
                DatatypeConverter.printHexBinary(Set1.challenge5(plainText, key)).toLowerCase());
    }

}

