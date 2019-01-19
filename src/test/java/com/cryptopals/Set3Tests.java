package com.cryptopals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.cryptopals.Set3.getKeyStream;
import static com.cryptopals.Set3.xorBlocks;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Test cases for Cryptopals Set 3 challenges")
public class Set3Tests {

    @Test @DisplayName("https://cryptopals.com/sets/1/challenges/17")
    /**
     * Since {@link Set3#challenge17Encrypt()} selects one of 10 strings to encrypt using a discreet uniform distribution,
     * we run the test as many times as is required to ensure that the probability of having tested each of the 10 strings'
     * encryptions is more than 0.1%.
     */
    void  challenge17() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        SecretKey key = aesKeyGen.generateKey();
        Set3   encryptor = new Set3(Cipher.ENCRYPT_MODE, key),  decryptor = new Set3(Cipher.DECRYPT_MODE, key);

        // Let p be the probability of choosing one of the Set3.CHALLENGE_17_UNKNOWN_PLAINTEXTS.length tests.
        // It is 1/Set3.CHALLENGE_17_UNKNOWN_PLAINTEXTS.length. We want to run the test n times, where n is the smallest
        // integer satisfying:
        // (1 - 1/Set3.CHALLENGE_17_UNKNOWN_PLAINTEXTS.length)^n < 0.001
        int n = (int) Math.ceil(Math.log(.001) / Math.log(1 - 1./Set3.CHALLENGE_17_UNKNOWN_PLAINTEXTS.length));
        for (int i=0; i < n; i++) {
            byte[]  cipherText = encryptor.challenge17Encrypt(),
                    plainText = Set3.breakChallenge17PaddingOracle(cipherText, decryptor.new Challenge17Oracle()),
                    cipherText_ = encryptor.cipherCBCChallenge17(plainText);
            assertArrayEquals(cipherText, cipherText_);
        }

    }

    @Test @DisplayName("https://cryptopals.com/sets/1/challenges/18")
    void  challenge18() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        Set3   encryptor = new Set3(Cipher.ENCRYPT_MODE, Set1.YELLOW_SUBMARINE_SK);
        assertEquals("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ",
                new String(encryptor.cipherCTR(Set3.CHALLENGE_18_CIPHERTEXT, 0)));
    }

    static class  Challenge20ArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments>  provideArguments(ExtensionContext context) throws IOException {
            ClassLoader classLoader = getClass().getClassLoader();
            Path path = Paths.get(Objects.requireNonNull(classLoader.getResource("challenge20_expected_plain.txt")).getFile()),
                 pathAlt = Paths.get(Objects.requireNonNull(classLoader.getResource("challenge20_expected_plain_alt.txt")).getFile());
            return Stream.of(
                    Arguments.of("challenge20.txt", Files.lines(path)),
                    Arguments.of("challenge20_alt.txt", Files.lines(pathAlt).map(
                            s -> s.replaceAll("\\\\r", "\r"))));
        }
    }

    @DisplayName("https://cryptopals.com/sets/1/challenges/20")
    @ParameterizedTest @ArgumentsSource(Challenge20ArgumentsProvider.class)
    void  challenge20(String fileName, Stream<String> expectedResult) throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource(fileName)).getFile());
        List<byte[]>   cipherTexts = Set1.readFileLines(file.toURI().toURL().toString(), Set1.Encoding.BASE64);
        int   keyStream[] = getKeyStream(cipherTexts);
        assertArrayEquals(expectedResult.toArray(),
            cipherTexts.stream().map(block -> new String(xorBlocks(block, keyStream))).toArray());
    }

    static class  Challenge21ArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments>  provideArguments(ExtensionContext context) throws IOException {
            int   res[] = { 37, 0, 53, 29, 11, 46, 15, 61, 57, 31, 47, 61, 4, 0, 34, 7, 47, 32, 36, 9, 58, 2, 12, 39,
                            5, 37, 23, 62, 20, 17, 41, 23, 54, 19, 18, 42, 54, 42, 41, 16, 17, 6, 31, 23, 55, 30, 63, 47,
                            43, 30, 27, 35, 56, 62, 7, 8, 6, 31, 14, 57, 57, 26, 46, 33, 22, 51, 8, 30, 33, 8, 7, 13, 38,
                            37, 5, 49, 60, 22, 40, 22, 8, 6, 19, 41, 4, 7, 39, 8, 62, 53, 24, 12, 11, 21, 2, 15, 63, 48,
                            17, 11, };
            return Stream.of(Arguments.of(5489L, res));

        }
    }
    @DisplayName("https://cryptopals.com/sets/1/challenges/21")
    @ParameterizedTest @ArgumentsSource(Challenge21ArgumentsProvider.class)
    void  challenge21(long seed, int expectedResult[])  {
        Random r = new MT19937(seed);
        assertArrayEquals(expectedResult,
                IntStream.range(0, 100).map(x -> r.nextInt(64)).toArray());
    }
}
