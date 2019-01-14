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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;
import java.util.stream.Stream;

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
        Set3   encryptor = new Set3(Cipher.ENCRYPT_MODE, key),
                decryptor = new Set3(Cipher.DECRYPT_MODE, key);


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
}
