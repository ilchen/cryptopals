package com.cryptopals;

import lombok.SneakyThrows;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by ilchen on 03/01/2019.
 */
public class Set2 {
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
        Random   randGen = new Random();
        int    numBytesToPad = randGen.nextInt(6);
        byte   paddedPlainText[] = new byte[plainText.length + numBytesToPad << 1],  padByte = 'P';
        System.arraycopy(plainText, 0, paddedPlainText, numBytesToPad, plainText.length);
        Arrays.fill(paddedPlainText, 0, numBytesToPad, padByte);
        Arrays.fill(paddedPlainText, plainText.length + numBytesToPad, numBytesToPad, padByte);
        if (randGen.nextBoolean()) {
            // Using the CBC mode
            byte   iv[] = new byte[cipher.getBlockSize()];
            new SecureRandom().nextBytes(iv); /* Generate a secure random IV */
            return  cipherCBC(paddedPlainText, iv);
        } else {
            return  cipherECB(paddedPlainText);
        }
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

            KeyGenerator   aesKeyGen = KeyGenerator.getInstance("AES");
            aesKeyGen.init(128);
            Set2   challenge11 = new Set2(aes, Cipher.ENCRYPT_MODE, aesKeyGen.generateKey());


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
