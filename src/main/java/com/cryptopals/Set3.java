package com.cryptopals;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.function.Predicate;

/**
 * Created by Andrei Ilchenko on 13-01-19.
 */
public class Set3 extends Set2 {
    static final byte CHALLENGE_17_UNKNOWN_PLAINTEXTS[][] = {
            DatatypeConverter.parseBase64Binary("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
            DatatypeConverter.parseBase64Binary("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
            DatatypeConverter.parseBase64Binary("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
            DatatypeConverter.parseBase64Binary("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
            DatatypeConverter.parseBase64Binary("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
            DatatypeConverter.parseBase64Binary("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
            DatatypeConverter.parseBase64Binary("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
            DatatypeConverter.parseBase64Binary("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
            DatatypeConverter.parseBase64Binary("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
            DatatypeConverter.parseBase64Binary("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
    };
    private static final int   BLOCK_SIZE = 0x10;

    private byte   randomIV[];

    Set3(int mode, SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        super(mode, key);
        randomIV = new byte[cipher.getBlockSize()];
        secRandGen.nextBytes(randomIV);
    }

    /**
     * Needed only to test the correctness of the implementation of Challenge 17
     */
    byte[] cipherCBCChallenge17(byte[] plainText) {
        byte   cipherText[] = cipherCBC(plainText, randomIV);
        // As customary, let's prepend the randomIV to the ciphertext.
        byte   fullCipherText[] = new byte[cipherText.length + randomIV.length];
        System.arraycopy(randomIV, 0, fullCipherText, 0, randomIV.length);
        System.arraycopy(cipherText, 0, fullCipherText, randomIV.length, cipherText.length);
        return  fullCipherText;
    }

    byte[] challenge17Encrypt() {
        int    stringNum = randGen.nextInt(CHALLENGE_17_UNKNOWN_PLAINTEXTS.length);
        byte   cipherText[] = cipherCBC(CHALLENGE_17_UNKNOWN_PLAINTEXTS[stringNum], randomIV);
        // As customary, let's prepend the randomIV to the ciphertext.
        byte   fullCipherText[] = new byte[cipherText.length + randomIV.length];
        System.arraycopy(randomIV, 0, fullCipherText, 0, randomIV.length);
        System.arraycopy(cipherText, 0, fullCipherText, randomIV.length, cipherText.length);
        return  fullCipherText;
    }

    @Override
    void paddingHook(byte[] plainText) throws BadPaddingException {
        triggerExceptionOnInvalidPKCS7Padding(plainText);
    }

    class Challenge17Oracle implements Predicate<byte[]> {
        @Override
        public boolean test(byte[] bytes) {
            int   blockSize = cipher.getBlockSize();
            byte[]  iv = Arrays.copyOf(bytes, blockSize),
                    cipherText = Arrays.copyOfRange(bytes, blockSize, bytes.length);
            try {
                decipherCBC(cipherText, iv);
                return  true;
            } catch (BadPaddingException e) {
                return  false;
            }
        }
    }


    /**
     * @param cipherText  an AES CBC encrypted message containing the IV
     * @return  the corresponding plain text
     */
    static byte[]  breakChallenge17PaddingOracle(byte cipherText[], Predicate<byte[]> oracle) {
        if (cipherText.length <= BLOCK_SIZE << 1  ||  cipherText.length % BLOCK_SIZE != 0) {
            throw  new IllegalArgumentException('\'' + new String(cipherText)
                    + "' is not a hex-encoded AES CBC encrypted message.");
        }

        int numBlocks = cipherText.length / BLOCK_SIZE;
        // Assuming that the first cipherblock is the IV.
        byte   res[] = new byte[cipherText.length - BLOCK_SIZE];
        byte   newBlock[];

        for (int i=0; i < numBlocks - 1; i++) {
            newBlock = Arrays.copyOfRange(cipherText, 0, (i + 2) * BLOCK_SIZE);
            NEXT_BYTE:
            for (int j = BLOCK_SIZE - 1, k = 1; j >= 0; j--, k++) {
                newBlock[i * BLOCK_SIZE + j] ^= k;
                for (byte b=0; b >= 0; b++) {
                    if (b == k  &&  k == 1)  continue;   /* Otherwise we might think we produced a valid pad ourselves */
                    newBlock[i * BLOCK_SIZE + j] ^= b;
                    if (oracle.test(newBlock)) {
                        res[i * BLOCK_SIZE + j] = b;
                        // prepare for the next byte
                        if (j == 0) break NEXT_BYTE;
                        for (int q = j; q < BLOCK_SIZE; q++) {
                            newBlock[i * BLOCK_SIZE + q] ^= k ^ k + 1;
                        }
                        break;
                    }
                    newBlock[i * BLOCK_SIZE + j] ^= b;
                }
            }

        }
        return  stripPKCS7Padding(res);
    }

    public static void main(String[] args) {

        try {
            // Import DST Root CA X3 certificate into $JAVA_HOME/jre/lib/security/cacerts or uncomment the next line
            // Set1.suppressSSLServerCertificateChecks();

            KeyGenerator   aesKeyGen = KeyGenerator.getInstance("AES");
            SecretKey      key = aesKeyGen.generateKey();
            Set3   encryptor = new Set3(Cipher.ENCRYPT_MODE, key),
                   decryptor = new Set3(Cipher.DECRYPT_MODE, key);
            byte[]   cipherText = encryptor.challenge17Encrypt(),
                     plainText = breakChallenge17PaddingOracle(cipherText, decryptor.new Challenge17Oracle());
            System.out.printf("Challenge 17%nBroken plaintext is: %s", new String(plainText));


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
