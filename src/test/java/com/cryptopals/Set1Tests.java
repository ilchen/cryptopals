package com.cryptopals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;
import java.util.stream.Stream;

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
        assertEquals(Set1.FrequencyAnalysisHelper.builder().score(2.14329f).key('X')
                .possiblePlainText("Cooking MC's like a pound of bacon".getBytes()).build(), res);

    }

    @DisplayName("https://cryptopals.com/sets/1/challenges/4")
    @ParameterizedTest @ArgumentsSource(Challenge4ArgumentsProvider.class)
    void  challenge4(String fileName, List<Set1.FrequencyAnalysisReportingHelper> expectedResult) throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource(fileName)).getFile());
        List<Set1.FrequencyAnalysisReportingHelper> cands = Set1.challenge4(file.toURI().toURL().toString());
        assertAll("Candidates",
                () -> {
                    assertEquals(expectedResult.size(), cands.size());
                    for (int i = 0; i < expectedResult.size(); i++) {
                        assertEquals(expectedResult.get(i), cands.get(i));
                    }
                }

        );
    }

    static class  Challenge4ArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments>  provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of("challenge4.txt",
                            Collections.singletonList(Set1.FrequencyAnalysisReportingHelper.builder()
                                    .line(170)
                                    .cipherText("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")
                                    .candInfo(
                                            Set1.FrequencyAnalysisHelper.builder().score(2.03479f).key('5')
                                                    .possiblePlainText("Now that the party is jumping\n".getBytes())
                                                    .build())
                                    .build())));
        }
    }

    @Test @DisplayName("https://cryptopals.com/sets/1/challenges/5")
    void  challenge5() {
        String   plainText = "Burning 'em, if you ain't quick and nimble\n" + "I go crazy when I hear a cymbal",
                 key = "ICE";
        assertEquals("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
                "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
                DatatypeConverter.printHexBinary(Set1.challenge5(plainText, key)).toLowerCase());
    }


    static class  Challenge6ArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments>  provideArguments(ExtensionContext context) throws FileNotFoundException {
            ClassLoader classLoader = getClass().getClassLoader();
            File f = new File(Objects.requireNonNull(classLoader.getResource("challenge6_expected_plain.txt")).getFile());
                        return Stream.of(
                    Arguments.of("challenge6.txt",
                            Set1.VigenereCipherAttackReporter.builder()
                                    .keySize(29).key("Terminator X: Bring the noise")
                                    .plainText(new Scanner(f).useDelimiter("\\Z").next()).build()));
        }
    }

    @DisplayName("https://cryptopals.com/sets/1/challenges/6")
    @ParameterizedTest @ArgumentsSource(Challenge6ArgumentsProvider.class)
    void  challenge6(String fileName, Set1.VigenereCipherAttackReporter expectedResult) throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource(fileName)).getFile());
        List<Set1.VigenereCipherAttackReporter> cands = Set1.challenge6(file.toURI().toURL().toString());
        int  i = cands.indexOf(expectedResult);
        assertAll("challenge6",
                () -> assertTrue(i >= 0),
                () -> assertEquals(5, cands.size()),
                () -> assertEquals(expectedResult, cands.get(i)) );
    }

    static class  Challenge7ArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments>  provideArguments(ExtensionContext context) throws FileNotFoundException {
            ClassLoader classLoader = getClass().getClassLoader();
            File f = new File(Objects.requireNonNull(classLoader.getResource("challenge6_expected_plain.txt")).getFile());
            return Stream.of(
                    Arguments.of("challenge7.txt",
                            new Scanner(f).useDelimiter("\\Z").next()));
        }
    }

    @DisplayName("https://cryptopals.com/sets/1/challenges/7")
    @ParameterizedTest @ArgumentsSource(Challenge7ArgumentsProvider.class)
    void  challenge7(String fileName, String expectedResult) throws IOException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource(fileName)).getFile());
        String plainText = new String(Set1.challenge7(file.toURI().toURL().toString()));
        assertEquals(expectedResult, plainText);
    }

    static class  Challenge8ArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments>  provideArguments(ExtensionContext context) throws FileNotFoundException {
            ClassLoader classLoader = getClass().getClassLoader();
            File f = new File(Objects.requireNonNull(classLoader.getResource("challenge8_expected_cipher.txt")).getFile());
            return Stream.of(
                    Arguments.of("challenge8.txt", Set1.FrequencyAnalysisReportingHelper
                            .builder().line(132).cipherText(new Scanner(f).useDelimiter("\\Z").next()).build()));
        }
    }

    @DisplayName("https://cryptopals.com/sets/1/challenges/8")
    @ParameterizedTest @ArgumentsSource(Challenge8ArgumentsProvider.class)
    void  challenge8(String fileName, Set1.FrequencyAnalysisReportingHelper expectedResult) throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource(fileName)).getFile());
        Set1.FrequencyAnalysisReportingHelper res = Set1.challenge8(file.toURI().toURL().toString());
        assertEquals(expectedResult, res);
    }
}

