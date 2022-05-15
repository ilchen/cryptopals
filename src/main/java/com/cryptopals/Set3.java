package com.cryptopals;

import lombok.Data;

import javax.crypto.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Created by Andrei Ilchenko on 13-01-19.
 */
public class Set3 extends Set2 {
    static final byte CHALLENGE_17_UNKNOWN_PLAINTEXTS[][] = {
            Base64.getDecoder().decode("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
            Base64.getDecoder().decode("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
            Base64.getDecoder().decode("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
            Base64.getDecoder().decode("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
            Base64.getDecoder().decode("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
            Base64.getDecoder().decode("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
            Base64.getDecoder().decode("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
            Base64.getDecoder().decode("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
            Base64.getDecoder().decode("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
            Base64.getDecoder().decode("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
        },
        CHALLENGE_18_CIPHERTEXT[] = Base64.getDecoder().decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    private static final int   BLOCK_SIZE = 0x10;

    private byte   randomIV[];

    public Set3(int mode, SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
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

    // Needed for Challenge 25
    byte[]  cipherCTR(byte[] plainText) {
        return  cipherCTR(plainText, ByteBuffer.wrap(Arrays.copyOf(randomIV, 8)).getLong());
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

    protected byte[]  cipherCTR(byte[] plainText, byte[] ctr) {
        byte[]   res = new byte[(plainText.length + 15) / 16 * 16],  curBlock,  randomPad;
        int      i = 0;
        BigInteger   ivCounter  = new BigInteger(Arrays.copyOfRange(ctr, 0, 16));

        for (; i < plainText.length; i+=16) {
            randomPad = cipher.update(ctr);
            curBlock = Arrays.copyOfRange(plainText, i, i+16);
            Set2.xorBlock(randomPad, curBlock);
            System.arraycopy(randomPad, 0, res, i, 16);
            ivCounter = ivCounter.add(BigInteger.ONE);
            ctr = ivCounter.toByteArray();
        }

        return  i == plainText.length  ?  res : Arrays.copyOf(res, plainText.length);
    }

    private byte[]  cipherMT19937(byte[] plainText) {
        return  cipherMT19937(plainText, ByteBuffer.wrap(Arrays.copyOf(randomIV, 2)).getShort());
    }

    static byte[]  cipherMT19937(byte[] plainText, short seed) {
        Random  r = new MT19937(seed);
        byte    res[] = new byte[plainText.length];
        r.nextBytes(res);
        xorBlock(res, plainText);
        return  res;
    }

    class Challenge24Oracle implements UnaryOperator<byte[]> {
        @Override
        public byte[] apply(byte[] knownPlainText) {
            byte[]  plainText = new byte[randPfx.length + knownPlainText.length];
            System.arraycopy(randPfx, 0, plainText, 0, randPfx.length);
            System.arraycopy(knownPlainText, 0, plainText, randPfx.length, knownPlainText.length);
            return  cipherMT19937(plainText);
        }
    }

    static short  breakChallenge24Oracle(byte knownPlainText[], UnaryOperator<byte[]> oracle) {
        byte[]  cipherText = oracle.apply(knownPlainText),  paddedPlainText = new byte[cipherText.length],
                cipherTextWithoutPfx = Arrays.copyOfRange(cipherText, cipherText.length - knownPlainText.length, cipherText.length);
        System.arraycopy(knownPlainText, 0, paddedPlainText, cipherText.length - knownPlainText.length, knownPlainText.length);
//        for (int seed=0; seed < 0xffff; seed++) {
//            byte[]   newCipherText = cipherMT19937(paddedPlainText, (short) seed),
//                    newCipherTextWithoutPfx = Arrays.copyOfRange(newCipherText, newCipherText.length - knownPlainText.length, newCipherText.length);
//            if (Arrays.equals(newCipherTextWithoutPfx, cipherTextWithoutPfx)) {
//                return  (short) seed;
//            }
//        }
//        throw new IllegalStateException("No seed found");
        // Below code is a factor of a 4 faster than the above single-threaded solution when tried on Intel Core i7
        return  (short) IntStream.range(0, 0xffff).parallel().filter(seed -> {
            byte[]   newCipherText = cipherMT19937(paddedPlainText, (short) seed),
                    newCipherTextWithoutPfx = Arrays.copyOfRange(newCipherText, newCipherText.length - knownPlainText.length, newCipherText.length);
            return  Arrays.equals(newCipherTextWithoutPfx, cipherTextWithoutPfx);
        }).findFirst().orElseThrow(IllegalStateException::new);

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

    @Data
    static class  MT19937Tap {
        private final int[]   mt = new int[MT19937.N];
        private int  mti = 0;

        void  tapNext(int val) {
            val = untemperRightShiftXor(val, MT19937.L);
            val = untemperLeftShiftAndXor(val, MT19937.T, MT19937.C);
            val = untemperLeftShiftAndXor(val, MT19937.S, MT19937.B);
            mt[mti++] = untemperRightShiftXor(val, MT19937.U);
        }

        static int  untemperLeftShiftAndXor(int val, int shift, int mask) {
//            y ^= y << MT19937.T (15) &  MT19937.C (0xEFC60000);
            if (shift >= MT19937.W / 2) {
                val ^= val << shift & mask;
            } else if ((MT19937.W / 2 - shift) << 1 < shift) {
                int  t = val;
                t ^= t << shift & mask;
                val ^= t << shift & mask;
            } else {
                int   t,  tNew = val;
                for (int i=MT19937.W-shift; i >=0; i-=shift) {
                    t = val;
                    t ^= tNew << shift & mask;
                    tNew = t;
                }
                val = tNew;
            }
            return  val;
        }

        static int  untemperRightShiftXor(int val, int shift) {
            if (shift >= MT19937.W / 2) {
                val ^= val >>> shift;
            } else if ((MT19937.W / 2 - shift) << 1 < shift) {
                int  t = val;
                t ^= t >>> shift;
                val ^= t >>> shift;
            } else {
                int   t,  tNew = val;
                for (int i=MT19937.W-shift; i >=0; i-=shift) {
                    t = val;
                    t ^= tNew >>> shift;
                    tNew = t;
                }
                val = tNew;
            }
            return  val;
            /*
             10110111010 11111000100 0011001110 ^
             00000000000 10110111010 1111100010
             ----------------------------------
             10110111010 01001111110 1100101100
                         10110111010 0100111111
             */
        }
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

            System.out.println("\nChallenge 21\nThe first 100 6bit integers from MT19937 PRNG are:");
            Random r = new MT19937();
            IntStream.range(0, 100).map(x -> r.nextInt(64)).forEach(x -> System.out.print(x + ", "));

            System.out.println("\n\nChallenge 23");
            Random r2 = new MT19937();
            MT19937Tap   tap = new MT19937Tap();
            IntStream.range(0, MT19937.N / 2).mapToLong(x -> r2.nextLong()).forEach(x -> {
                int   i = (int) x;
                tap.tapNext((int) ((x - i) >> 32));   tap.tapNext(i); }  );
            Random r2Cloned = new MT19937(tap.getMti(), tap.getMt());
            System.out.println("The difference between the two generators should be zero if they return the same values");
            IntStream.range(0, 32).map(x -> r2.nextInt(64) - r2Cloned.nextInt(64)).forEach(x -> System.out.print(x + ", "));

            System.out.println("\n\nChallenge 24");
            plainText = "AAAAAAAaaaaaaa".getBytes();
            long  start,  end;
            int   n = 100;
            short k = 0;
            double   accu = 0.;
            UnaryOperator<byte[]>  oracle = encryptor.new Challenge24Oracle();
            for (int i=0; i < n; i++) {
                start = System.nanoTime();
                k = breakChallenge24Oracle(plainText, oracle);
                end = System.nanoTime();
                accu += end - start;
            }
            accu /= n;
            System.out.printf("Recovered key 0x%4x in %.6f seconds on average%n", k, accu / 1e9);
            cipherText = cipherMT19937(oracle.apply(plainText), k);
            System.out.printf("Expect to get '%s' when decripting with found key 0x%4x: '%s'%n", new String(plainText), k,
                    new String(Arrays.copyOfRange(cipherText, cipherText.length - plainText.length, cipherText.length)));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
