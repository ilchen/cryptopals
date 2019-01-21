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

import static com.cryptopals.Set1.challenge7;
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
}
