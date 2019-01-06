package com.cryptopals;

import lombok.SneakyThrows;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Created by ilchen on 03/01/2019.
 */
public class Set2 {
    private static final byte   CHALLENGE_12_UNKNOWN_PLAINTEXT[] = DatatypeConverter.parseBase64Binary(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            + "YnkK");
    private Cipher   cipher;

    public Set2(Cipher cipher, int mode, SecretKey key) throws InvalidKeyException {
        this.cipher = cipher;
        cipher.init(mode, key);
    }

    private static void   xorBlock(byte trg[], byte src[]) {
        for (int i=0; i < trg.length; i++) {
            trg[i] ^= src[i];
        }
    }

    private byte[]  pkcs7Pad(byte plainText[]) {
        final int   blockSize = cipher.getBlockSize(),
                    blockLenRem = plainText.length % blockSize,
                    padLen = blockLenRem == 0  ?  blockSize : blockSize - blockLenRem;
        byte   res[] = new byte[plainText.length + padLen];
        System.arraycopy(plainText, 0, res, 0, plainText.length);
        Arrays.fill(res, plainText.length, res.length, (byte) padLen);
        return  res;
    }

    @SneakyThrows  /* Padding and blocksize-related checked exceptions excluded */
    private byte[]  cipherECB(byte plainText[]) {
        byte paddedPlainText[] = pkcs7Pad(plainText);
        return  cipher.doFinal(paddedPlainText);
    }

    private byte[]  cipherCBC(byte plainText[], byte iv[]) {
        byte paddedPlainText[] = pkcs7Pad(plainText);
        byte res[] = new byte[paddedPlainText.length];
        final int   blockSize = cipher.getBlockSize();

        byte   prevCipherBlock[] = iv,  curBlock[];
        int    i = 0;
        for (; i < paddedPlainText.length; i+=blockSize) {
            curBlock = Arrays.copyOfRange(plainText, i, i+blockSize);
            xorBlock(curBlock, prevCipherBlock);
            prevCipherBlock = cipher.update(curBlock);
            System.arraycopy(prevCipherBlock, 0, res, i, blockSize);
        }
        return  res;
    }

    private byte[]  decipherCBC(byte cipherText[], byte iv[]) {
        byte res[] = new byte[cipherText.length];
        final int   blockSize = cipher.getBlockSize();

        byte   prevCipherBlock[] = iv,  curCipherBlock[];
        byte   plainTextBlock[];
        int    i = 0;
        for (; i < cipherText.length-blockSize; i+=blockSize) {
            curCipherBlock = Arrays.copyOfRange(cipherText, i, i+blockSize);
            xorBlock((plainTextBlock = cipher.update(curCipherBlock)), prevCipherBlock);
            System.arraycopy(plainTextBlock, 0, res, i, blockSize);
            prevCipherBlock = curCipherBlock;
        }

        // And now the final block
        xorBlock((plainTextBlock = cipher.update(Arrays.copyOfRange(cipherText, i, i + blockSize))), prevCipherBlock);
        System.arraycopy(plainTextBlock, 0, res, i, blockSize);

        // Now we need to deal with padding. NB: alternatively I could've initialized the cipher
        // with Cipher.getInstance("AES/ECB/PKCS5Padding") to forgo dealing with padding myself, but that would've
        // required deciphering the last block with 'doFinal'
        res = Arrays.copyOf(res, res.length - res[res.length-1]);
        return  res;
    }

    private byte[]  encryptionOracle(byte plainText[]) throws NoSuchAlgorithmException {
        Random   randGen = new Random(),   secRandGen = new SecureRandom();
        int    numBytesToPad = randGen.nextInt(6);
        byte   paddedPlainText[] = new byte[plainText.length + numBytesToPad << 1],  pad[] = new byte[numBytesToPad];
        System.arraycopy(plainText, 0, paddedPlainText, numBytesToPad, plainText.length);
        secRandGen.nextBytes(pad);
        System.arraycopy(pad, 0, paddedPlainText, 0, numBytesToPad);
        secRandGen.nextBytes(pad);
        System.arraycopy(pad, 0, paddedPlainText,plainText.length + numBytesToPad, numBytesToPad);
        if (randGen.nextBoolean()) {
            System.out.println("Encrypting " + new String(plainText) + " using CBC");
            // Using the CBC mode
            byte   iv[] = new byte[cipher.getBlockSize()];
            secRandGen.nextBytes(iv); /* Generate a secure random IV */
            return  cipherCBC(paddedPlainText, iv);
        } else {
            System.out.println("Encrypting " + new String(plainText) + " using ECB");
            return  cipherECB(paddedPlainText);
        }
    }

    private boolean  isECB(byte cipherText[], double threashold) {
        int   blockSize = cipher.getBlockSize(),  numBlocks = cipherText.length / blockSize;
        // Under ECB we have an equality Ci == Cj => Pi == Pj.
        // Under CBC we have a different equality: Ci == Cj => Pi ^ Pj == Ci-1 ^ Cj-1.
        return  Set1.countUniqueCipherBlocks(cipherText, blockSize) / (double) numBlocks < threashold;
    }

    private byte[] challenge12Oracle(byte[] myPlainText, byte[] unknownPlainText) {
        byte   plainText[] = new byte[myPlainText.length + unknownPlainText.length];
        System.arraycopy(myPlainText, 0, plainText, 0, myPlainText.length);
        System.arraycopy(unknownPlainText, 0, plainText, myPlainText.length, unknownPlainText.length);
        return  cipherECB(plainText);
    }

    private int  detectBlockSize(byte unknownPlainText[]) {
        StringBuilder   sb = new StringBuilder();
        int    cipherTextSize = challenge12Oracle(new byte[0], unknownPlainText).length;
        int    blockSize;

        // Let's detect the block size
        do {
            sb.append('A');
            blockSize = challenge12Oracle(sb.toString().getBytes(), unknownPlainText).length;
        } while (blockSize == cipherTextSize);
        return blockSize - cipherTextSize;
    }

    private byte[]  uncoverPlainText(int blockSize, byte unknownPlainText[]) {
        byte[]   testBlock = new byte[blockSize],  res = new byte[unknownPlainText.length];
        Arrays.fill(testBlock, (byte) 'A');

        // Now let's build a dictionary
        Map<ByteBuffer, Byte> dict = new HashMap<>();
        for (int ch = 0; ch < 256; ch++) {
            testBlock[blockSize-1] = (byte) ch;
            dict.put(ByteBuffer.wrap(challenge12Oracle(testBlock, unknownPlainText), 0, blockSize), (byte) ch);
        }

        testBlock = Arrays.copyOf(testBlock, blockSize - 1);
        for (int i=0; i < unknownPlainText.length; i++) {
            byte   shiftedPlainText[] = Arrays.copyOfRange(unknownPlainText, i, unknownPlainText.length);
            res[i] = dict.get(ByteBuffer.wrap(challenge12Oracle(testBlock, shiftedPlainText), 0, blockSize));

        }

        // Now let's deal with
        return  res;
    }

    public static void main(String[] args) {

        try {
            // Import DST Root CA X3 certificate into $JAVA_HOME/jre/lib/security/cacerts or uncomment the next line
            // Set1.suppressSSLServerCertificateChecks();

            Cipher   aes = Cipher.getInstance("AES/ECB/NoPadding");
            Set2   challenge10 = new Set2(aes, Cipher.DECRYPT_MODE, Set1.YELLOW_SUBMARINE_SK);
            byte[]  cipherText = Set1.readFile(
                    "https://cryptopals.com/static/challenge-data/10.txt", Set1.Encoding.BASE64),
                    iv = {  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  },
                    plainText = challenge10.decipherCBC(cipherText, iv);
            System.out.println("Challenge 10\tPlain text:\n" + new String(plainText));



            System.out.println("Challenge 11");
            String   tests[] = {"Test 1: 24xXXXXXXXXXXXXXXXXXXXXXXXX 23xYYYYYYYYYYYYYYYYYYYYYYY",
                                "Test 2: 24xXXXXXXXXXXXXXXXXXXXXXXXX"};
            KeyGenerator   aesKeyGen = KeyGenerator.getInstance("AES");
            aesKeyGen.init(128);
            for (String test : tests) {
                for (int j = 0; j < 10; j++) {
                    Set2 challenge11 = new Set2(aes, Cipher.ENCRYPT_MODE, aesKeyGen.generateKey());
                    cipherText = challenge11.encryptionOracle(test.getBytes());
                    System.out.println("Detected mode is: "
                            + (challenge11.isECB(cipherText, .9) ? "ECB" : "CBC"));
                }
            }

            System.out.println("\nChallenge 12");
            SecretKey   key = aesKeyGen.generateKey();
            Set2   challenge12 = new Set2(aes, Cipher.ENCRYPT_MODE, key);
            int   blockSize = challenge12.detectBlockSize(CHALLENGE_12_UNKNOWN_PLAINTEXT);

            // Let's confirm the Oracle is applying an ECB-mode encryption
            if (challenge12.isECB(
                    challenge12.challenge12Oracle("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".getBytes(),
                            CHALLENGE_12_UNKNOWN_PLAINTEXT), .91)) {

                // Now the real thing
                plainText = challenge12.uncoverPlainText(blockSize, CHALLENGE_12_UNKNOWN_PLAINTEXT);
                System.out.println("Plaintext: " + new String(plainText));
            } else {
                System.out.println("Not ECB mode encrypted :-(");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
