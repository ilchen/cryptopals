package com.cryptopals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static com.cryptopals.Set1.challenge7;
import static com.cryptopals.Set3.cipherMT19937;
import static org.junit.jupiter.api.Assertions.*;

public class Set4Tests {
    @DisplayName("https://cryptopals.com/sets/4/challenges/25")
    @ParameterizedTest @ArgumentsSource(Set1Tests.Challenge7ArgumentsProvider.class)
    void  challenge25(String fileName, String expectedResult) throws IOException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(Objects.requireNonNull(classLoader.getResource(fileName)).getFile());
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        SecretKey key = aesKeyGen.generateKey();
        Set4   encryptor = new Set4(Cipher.ENCRYPT_MODE, key);
        byte[]   unknownPlainText = Set1.challenge7(file.toURI().toURL().toString()),
                cipherText = encryptor.cipherCTR(unknownPlainText),
                recoveredPlainText = Set4.breakChallenge25Oracle(cipherText, encryptor.new Challenge25Oracle());
        assertEquals(expectedResult, new String(recoveredPlainText));
    }

    @DisplayName("https://cryptopals.com/sets/4/challenges/27")
    @Test
    void  challenge27() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        SecretKey key = aesKeyGen.generateKey();
        Set4   encryptor = new Set4(Cipher.ENCRYPT_MODE, key);
        Set2   decryptor = new Set2(Cipher.DECRYPT_MODE, key);

        Set4.Challenge27Oracle challenge27Oracle = encryptor.new Challenge27Oracle(
                Set2.CHALLANGE_16_QUERY_STRING_PREFIX.getBytes(),
                Set2.CHALLANGE_16_QUERY_STRING_SUFFIX.getBytes());
        byte   k[] = Set4.breakChallenge27Oracle(decryptor, challenge27Oracle);
        assertArrayEquals(key.getEncoded(), k);
    }
}
