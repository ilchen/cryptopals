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
import java.util.function.UnaryOperator;

/**
 * Created by ilchen on 03/01/2019.
 */
public class Set2 {
    private static final byte   CHALLENGE_12_UNKNOWN_PLAINTEXT[] = DatatypeConverter.parseBase64Binary(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            + "YnkK");
    private static final String  AES_TRANSFORMATION = "AES/ECB/NoPadding";
    private Cipher   cipher;
    private Random   randGen,  secRandGen;
    private byte     randPfx[];

    private Set2(int mode, SecretKey key) throws InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(mode, key);
        randGen = new Random();
        secRandGen = new SecureRandom();
        randPfx = new byte[randGen.nextInt(30)];
        secRandGen.nextBytes(randPfx);
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

        byte[]   prevCipherBlock = iv,  curBlock;
        int    i = 0;
        for (; i < paddedPlainText.length; i+=blockSize) {
            curBlock = Arrays.copyOfRange(paddedPlainText, i, i+blockSize);
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

        // Now we need to deal with padding.
        res = Arrays.copyOf(res, res.length - res[res.length-1]);
        return  res;
    }

    private byte[]  encryptionOracle(byte plainText[]) {
        int    numBytesToPad = randGen.nextInt(6);
        byte[]   paddedPlainText = new byte[plainText.length + numBytesToPad << 1],  pad = new byte[numBytesToPad];
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

    class Challenge12Oracle implements UnaryOperator<byte[]> {
        byte   unknownPlainText[];
        Challenge12Oracle(byte unknownPlainText[]) {
            this.unknownPlainText = unknownPlainText;
        }

        @Override
        public byte[] apply(byte[] myPlainText) {
            byte   plainText[] = new byte[myPlainText.length + unknownPlainText.length];
            System.arraycopy(myPlainText, 0, plainText, 0, myPlainText.length);
            System.arraycopy(unknownPlainText, 0, plainText, myPlainText.length, unknownPlainText.length);
            return  cipherECB(plainText);
        }

        int   getUnknownPlainTextLength() {
            return  unknownPlainText.length;
        }

        void dropLeftmostPlainTextByte() {
            unknownPlainText = Arrays.copyOfRange(unknownPlainText, 1, unknownPlainText.length);
        }

    }

    class Challenge14Oracle extends Challenge12Oracle {
        Challenge14Oracle(byte unknownPlainText[]) {
            super(unknownPlainText);
        }

        @Override
        public byte[] apply(byte[] myPlainText) {
            byte[]  plainText = new byte[randPfx.length + myPlainText.length + unknownPlainText.length];
            System.arraycopy(randPfx, 0, plainText, 0, randPfx.length);
            System.arraycopy(myPlainText, 0, plainText, randPfx.length, myPlainText.length);
            System.arraycopy(unknownPlainText, 0, plainText,
                    randPfx.length + myPlainText.length, unknownPlainText.length);
            return  cipherECB(plainText);
        }
    }

    private int  detectBlockSize(UnaryOperator<byte[]> oracle) {
        StringBuilder   sb = new StringBuilder();
        int    cipherTextSize = oracle.apply(new byte[0]).length;
        int    blockSize;

        // Let's detect the block size
        do {
            sb.append('A');
            blockSize = oracle.apply(sb.toString().getBytes()).length;
        } while (blockSize == cipherTextSize);
        return blockSize - cipherTextSize;
    }

    private byte[]  uncoverPlainText(int blockSize, Challenge12Oracle oracle) {
        byte[]   testBlock = new byte[blockSize],  res = new byte[oracle.getUnknownPlainTextLength()];
        Arrays.fill(testBlock, (byte) 'A');

        // Now let's build a dictionary
        Map<ByteBuffer, Byte> dict = new HashMap<>();
        for (int ch = 0; ch < 256; ch++) {
            testBlock[blockSize-1] = (byte) ch;
            dict.put(ByteBuffer.wrap(oracle.apply(testBlock), 0, blockSize), (byte) ch);
        }

        testBlock = Arrays.copyOf(testBlock, blockSize - 1);
        for (int i=0; i < res.length; i++, oracle.dropLeftmostPlainTextByte()) {
            res[i] = dict.get(ByteBuffer.wrap(oracle.apply(testBlock), 0, blockSize));
        }

        return  res;
    }

    private int detectPrefixLength(int blockSize, Challenge12Oracle oracle) {
        // We need to ensure that the length of the array we control plus the length of the unknown plain text
        // we want to decipher is a multiple of the blocksize.
        StringBuilder   sb = new StringBuilder();
        int   unknownPlainTextLen = oracle.getUnknownPlainTextLength();
        int   padSize = blockSize - unknownPlainTextLen % blockSize;
        if (unknownPlainTextLen % blockSize != 0) {
            for (int i=0; i < padSize; i++)  {
                sb.append('A');
            }
        }

        int   cipherTextSize = oracle.apply(sb.toString().getBytes()).length;
        int   pfxOffset = 0;

        // Let's detect the prefix offset
        do {
            sb.append('A');
            pfxOffset++;
        } while (oracle.apply(sb.toString().getBytes()).length == cipherTextSize);
        return  (pfxOffset == 1  ?  0 : blockSize - pfxOffset)
                + cipherTextSize - unknownPlainTextLen - padSize - blockSize;
    }

    private byte[]  uncoverPlainTextHarder(int blockSize, int pfxLength, Challenge12Oracle oracle) {
        int      lenPad = blockSize - pfxLength % blockSize,  offset = pfxLength / blockSize * blockSize;
        byte[]   testBlock = new byte[lenPad],  res = new byte[oracle.getUnknownPlainTextLength()];
        Arrays.fill(testBlock, (byte) 'A');

        // Now let's build a dictionary
        Map<ByteBuffer, Byte> dict = new HashMap<>();
        for (int ch = 0; ch < 256; ch++) {
            testBlock[lenPad-1] = (byte) ch;
            dict.put(ByteBuffer.wrap(oracle.apply(testBlock), offset, blockSize), (byte) ch);
        }

        testBlock = Arrays.copyOf(testBlock, lenPad - 1);
        for (int i=0; i < res.length; i++, oracle.dropLeftmostPlainTextByte()) {
            res[i] = dict.get(ByteBuffer.wrap(oracle.apply(testBlock), offset, blockSize));
        }

        return  res;
    }

    private void  triggerExceptionOnInvalidPKCS7Padding(byte plainText[]) throws BadPaddingException  {
        int   blockSize = cipher.getBlockSize();
        byte  padVal = plainText[plainText.length - 1];
        if (plainText.length >= blockSize  &&  plainText.length % blockSize == 0   &&  padVal <= blockSize) {
            for (int i=plainText.length-2; i >= plainText.length - padVal; i--) {
                if (plainText[i] != padVal)  throw  new BadPaddingException();
            }
            return;
        }
        throw  new BadPaddingException();
    }

    class  Challenge16Oracle extends Challenge12Oracle {
        byte[]   iv,  unknownPrefix;
        Challenge16Oracle(byte[] unknownPrefix, byte[] unknownPlainText, byte iv[]) {
            super(unknownPlainText);
            this.iv = iv;
            this.unknownPrefix = unknownPrefix;
        }

        byte[] apply(String myPlainText) {
            return apply(myPlainText.replace("=", "%3d").replace(";", "%3b").getBytes());
        }

        @Override
        public byte[] apply(byte[] myPlainText) {
            byte  fullPlainText[] = new byte[myPlainText.length + unknownPrefix.length + unknownPlainText.length];
            System.arraycopy(unknownPrefix, 0, fullPlainText, 0, unknownPrefix.length);
            System.arraycopy(myPlainText, 0, fullPlainText, unknownPrefix.length, myPlainText.length);
            System.arraycopy(unknownPlainText, 0, fullPlainText,
                    unknownPrefix.length + myPlainText.length, unknownPlainText.length);
            return cipherCBC(fullPlainText, iv);
        }

        private boolean  isExpectedParamPresent(byte cipherText[], Set2 decryptor) {
            return  new String(decryptor.decipherCBC(cipherText, iv)).contains(";admin=true;");
        }
    }

    void  breakChallenge16Oracle(Set2 decryptor, Challenge16Oracle challenge16Oracle) {
        // Now the actual challenge, which it to mount a CCA attack using the oracle to ensure that
        // we get a piece of crafted cipher text that forces the oracle to return true.
        // The left pad that 'challenge16Encrypt' prepends is 32 bytes long. So the piece of text
        // we control occupies the whole second block and possibly beyond.
        // The desired string we want to inject into the cipher text ";admin=true;" is 12 bytes long.
        String   craftedString = "\0admin\0true\0";
        int  blockLen = detectBlockSize(challenge16Oracle);
        int  pfxLen = detectPrefixLength(blockLen, challenge16Oracle);
        byte cipherText[] = challenge16Oracle.apply(craftedString);
        System.out.println("Submitting the encryption of the crafted string '" + craftedString
                + "' to the Oracle directly makes it return: "
                + challenge16Oracle.isExpectedParamPresent(cipherText, decryptor));

        // Now we need to modify the pfxLen+1th, the pfxLen+7th, and the pfxLen+12th bytes of the ciphertext
        cipherText[pfxLen - blockLen]      ^= (byte) ';';
        cipherText[pfxLen - blockLen + 6]  ^= (byte) '=';
        cipherText[pfxLen - blockLen + 11] ^= (byte) ';';
        System.out.println("Submitting the modified encryption of the crafted string '" + craftedString
                + "' to the Oracle directly makes it return: "
                + challenge16Oracle.isExpectedParamPresent(cipherText, decryptor));
    }

    public static void main(String[] args) {

        try {
            // Import DST Root CA X3 certificate into $JAVA_HOME/jre/lib/security/cacerts or uncomment the next line
            // Set1.suppressSSLServerCertificateChecks();


            Set2   challenge10 = new Set2(Cipher.DECRYPT_MODE, Set1.YELLOW_SUBMARINE_SK);
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
                    Set2 challenge11 = new Set2(Cipher.ENCRYPT_MODE, aesKeyGen.generateKey());
                    cipherText = challenge11.encryptionOracle(test.getBytes());
                    System.out.println("Detected mode is: "
                            + (challenge11.isECB(cipherText, .9) ? "ECB" : "CBC"));
                }
            }

            System.out.println("\nChallenge 12");
            SecretKey   key = aesKeyGen.generateKey();
            Set2   encryptor = new Set2(Cipher.ENCRYPT_MODE, key);
            Challenge12Oracle   challenge12Oracle = encryptor.new Challenge12Oracle(CHALLENGE_12_UNKNOWN_PLAINTEXT);
            int   blockSize = encryptor.detectBlockSize(challenge12Oracle);

            // Let's confirm the Oracle is applying an ECB-mode encryption
            if (encryptor.isECB(challenge12Oracle.apply("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".getBytes()), .91)) {
                // Now the real thing
                plainText = encryptor.uncoverPlainText(blockSize, challenge12Oracle);
                System.out.println("Plaintext: " + new String(plainText));
            } else {
                System.out.println("Not ECB mode encrypted :-(");
            }

            System.out.println("\nChallenge 14");
            Challenge14Oracle  challenge14Oracle = encryptor.new Challenge14Oracle(CHALLENGE_12_UNKNOWN_PLAINTEXT);
            int   pfxLength = encryptor.detectPrefixLength(blockSize, challenge14Oracle);
            plainText = encryptor.uncoverPlainTextHarder(blockSize, pfxLength, challenge14Oracle);
            System.out.println("Plaintext: " + new String(plainText));

            System.out.println("\nChallenge 15");
            String   tests2[] = { "ICE ICE BABY\4\4\4\4",  "ICE ICE BABY\5\5\5\5",  "ICE ICE BABY\1\2\3\4" };
            for (String test : tests2) try {
                System.out.print("Is '" + test + "' correctly padded? ");
                encryptor.triggerExceptionOnInvalidPKCS7Padding(test.getBytes());
                System.out.println("yes");
            } catch (BadPaddingException e) {
                System.out.println("no");
            }

            System.out.println("\nChallenge 16");
            String   challenge16SecretText[] = {
                    "Will anyone manage to break it?",
                    "Will anyone manage to break it? ;admin=true;" },  challenge16IV = "0123456789ABCdef";
            Challenge16Oracle challenge16Oracle = encryptor.new Challenge16Oracle(
                    "comment1=cooking%20MCs;userdata=".getBytes(),
                    ";comment2=%20like%20a%20pound%20of%20bacon".getBytes(), challenge16IV.getBytes());
            Set2   decryptor = new Set2(Cipher.DECRYPT_MODE, key);

            for (String sText : challenge16SecretText) {
                cipherText = challenge16Oracle.apply(sText);
                System.out.println("Oracle returned " + challenge16Oracle.isExpectedParamPresent(cipherText, decryptor));
            }
            encryptor.breakChallenge16Oracle(decryptor, challenge16Oracle);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
