package com.cryptopals;

import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

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
        },
        CHALLENGE_18_CIPHERTEXT[] = DatatypeConverter.parseBase64Binary("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
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
        byte[]  res = new byte[cipherText.length - BLOCK_SIZE],  newBlock;

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

    byte[]  cipherCTR(byte[] plainText, long nonce) {
        ByteBuffer   nonceBuf = ByteBuffer.allocate(2 * Long.BYTES).putLong(nonce).order(ByteOrder.LITTLE_ENDIAN);
        byte[]   res = new byte[(plainText.length + 15) / 16 * 16],  curPRF,  curBlock,  randomPad;
        int      i = 0;

        for (; i < plainText.length; i+=16) {
            curPRF = nonceBuf.duplicate().order(ByteOrder.LITTLE_ENDIAN).putLong(i / 16).array();
            randomPad = cipher.update(curPRF);
            curBlock = Arrays.copyOfRange(plainText, i, i+16);
            Set2.xorBlock(randomPad, curBlock);
            System.arraycopy(randomPad, 0, res, i, 16);
        }

        return  i == plainText.length  ?  res : Arrays.copyOf(res, plainText.length);
    }

    // If only there was Stream#mapToByte...
    static int[]  getKeyStream(List<byte[]> cipherTexts) {
        int   len = cipherTexts.stream().mapToInt(c -> c.length).min().orElseThrow(
                () -> new IllegalArgumentException("cipherTexts list is empty")),  num = cipherTexts.size();

        Stream<byte[]> blocks = IntStream.range(0, len).parallel().mapToObj(i -> {
            ByteBuffer  bb = ByteBuffer.allocate(num);
            for (byte[] cipherText : cipherTexts) {
                bb.put(cipherText[i]);
            }
            return bb.array();
        });

        return  blocks.mapToInt(block -> Set1.challenge3Helper(block).getKey()).toArray();
    }

    static byte[]  xorBlocks(byte text[], int keyStream[]) {
        byte   res[] = new byte[keyStream.length];
        for (int i=0; i < keyStream.length; i++) {
            res[i] = (byte) (text[i] ^ keyStream[i]);
        }
        return  res;
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
            System.out.printf("Challenge 17%nBroken plaintext is: %s%n", new String(plainText));

            encryptor = new Set3(Cipher.ENCRYPT_MODE, Set1.YELLOW_SUBMARINE_SK);
            System.out.printf("%nChallenge 18%nPlaintext: %s%n", new String(encryptor.cipherCTR(CHALLENGE_18_CIPHERTEXT, 0)));

            System.out.println("\nChallenge 20\nPlaintexts:");
            List<byte[]>   cipherTexts = Set1.readFileLines("https://cryptopals.com/static/challenge-data/20.txt",
                                                            Set1.Encoding.BASE64);
            int   keyStream[] = getKeyStream(cipherTexts);
            cipherTexts.stream().map(block -> new String(xorBlocks(block, keyStream))).forEach(System.out::println);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
