package com.cryptopals;

import lombok.Data;
import sun.security.provider.MD4;
import sun.security.provider.MD4Ext;
import sun.security.provider.SHA1;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.function.BiPredicate;
import java.util.function.LongUnaryOperator;
import java.util.stream.LongStream;

import static com.cryptopals.Set1.challenge7;

/**
 * Created by Andrei Ilchenko on 21-01-19.
 */
public class Set4 extends Set3 {
    public static final long   DELAY_MILLIS = 5;
    public static final int   HMAC_SIGNATURE_LENGTH = 10;
    static final String   CHALLANGE_29_ORIGINAL_MESSAGE = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",
                          CHALLANGE_29_EXTENSION = ";admin=true";
    private SecretKey  key;
    private MessageDigest   sha,  md4;

    public Set4(int mode, SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        super(mode, key);
        this.key = key;
        sha = MessageDigest.getInstance("SHA-1");
        md4 = MD4.getInstance();
    }

    byte[]  keyedMac(byte message[]) {
        sha.update(key.getEncoded());
        return  sha.digest(message);
    }

    byte[]  keyedMacMD4(byte message[]) {
        md4.update(key.getEncoded());
        return  md4.digest(message);
    }

    public byte[]  hmacSha1(byte message[]) {
        byte[] k = Arrays.copyOf(key.getEncoded(), 64),
                outerKeyPad = new byte[64],  innerKeyPad = new byte[64],  innerHash,  outerHash;
        for (int i=0; i < k.length; i++) {
            outerKeyPad[i] = (byte) (k[i] ^ 0x5c);
            innerKeyPad[i] = (byte) (k[i] ^ 0x36);
        }
        innerHash = Arrays.copyOf(innerKeyPad, message.length + k.length);
        System.arraycopy(message, 0, innerHash, k.length, message.length);
        innerHash = sha.digest(innerHash);
        outerHash = Arrays.copyOf(outerKeyPad, innerHash.length + k.length);
        System.arraycopy(innerHash, 0, outerHash, k.length, innerHash.length);
        return  sha.digest(outerHash);
    }

    public int  getHmacSha1DigestLength() {
        return  sha.getDigestLength();
    }

    interface CipherTextEditOracle {
        byte[] edit(byte cipherText[], int offset, byte newText[]);
    }
    class  Challenge25Oracle implements CipherTextEditOracle {
        public byte[] edit(byte cipherText[], int offset, byte newText[]) {
            byte plainText[] = cipherCTR(cipherText);
            if (offset + newText.length > plainText.length) {
                plainText = Arrays.copyOf(plainText, offset + newText.length);
            }
            System.arraycopy(newText, 0, plainText, offset, newText.length);
            return cipherCTR(plainText);
        }
    }

    static byte[]  breakChallenge25Oracle(byte cipherText[], CipherTextEditOracle oracle) {
        ByteBuffer  bb = ByteBuffer.allocate(cipherText.length);
        byte[]   b = new byte[1];
        for (int i=0; i < cipherText.length; i++) {
            for (char c=0; c < 256; c++) {
                b[0] = (byte) c;
                if (oracle.edit(cipherText, i, b)[i] == cipherText[i]) {
                    bb.put(b[0]);
                    break;
                }
            }
        }
        return  bb.array();
    }

    class  Challenge26Oracle extends Challenge16Oracle {
        Challenge26Oracle(byte[] unknownPrefix, byte[] unknownPlainText, long nonce) {
            super(unknownPrefix, unknownPlainText, ByteBuffer.allocate(Long.BYTES).putLong(nonce).array());
        }
        @Override
        byte[] doEncryption(byte[] text, byte[] iv) {
            return  cipherCTR(text, ByteBuffer.wrap(iv).getLong());
        }
        @Override
        boolean isExpectedParamPresent(byte[] cipherText, Set2 ignored) {
            return  new String(doEncryption(cipherText, iv)).contains(EXPECTED_PARAM);
        }
    }

    private static void  breakChallenge26Oracle(Challenge26Oracle challenge26Oracle) throws BadPaddingException {
        // Now the actual challenge, which it to mount a CCA attack using the oracle to ensure that
        // we get a piece of crafted cipher text that forces the oracle to return true.
        // The left pad that 'challenge16Encrypt' prepends is 32 bytes long. So the piece of text
        // we control occupies the whole second block and possibly beyond.
        // The desired string we want to inject into the cipher text ";admin=true;" is 12 bytes long.
        String   craftedString = "\0admin\0true\0";
        int  pfxLen = challenge26Oracle.apply("").length - challenge26Oracle.getUnknownPlainTextLength();
        byte[] cipherText = challenge26Oracle.apply(craftedString);
        System.out.println("Submitting the encryption of the crafted string '" + craftedString
                + "' to the Oracle directly makes it return: "
                + challenge26Oracle.isExpectedParamPresent(cipherText, null));

        // Now we need to modify the pfxLen+1th, the pfxLen+7th, and the pfxLen+12th bytes of the ciphertext
        cipherText[pfxLen]      ^= (byte) ';';
        cipherText[pfxLen + 6]  ^= (byte) '=';
        cipherText[pfxLen + 11] ^= (byte) ';';
        System.out.println("Submitting the modified encryption of the crafted string '" + craftedString
                + "' to the Oracle makes it return: "
                + challenge26Oracle.isExpectedParamPresent(cipherText, null));
    }

    static class  Challenge27OracleException extends IllegalArgumentException {
        private byte   plainText[];
        Challenge27OracleException(byte p[]) {
            plainText = p;
        }
        byte[] getPlainText() {
            return plainText;
        }
    }

    class  Challenge27Oracle extends Challenge16Oracle {
        Challenge27Oracle(byte[] unknownPrefix, byte[] unknownPlainText) {
            super(unknownPrefix, unknownPlainText, key.getEncoded());
        }

        @Override
        boolean isExpectedParamPresent(byte[] cipherText, Set2 decryptor) throws BadPaddingException {
            byte   plainText[] = decryptor.decipherCBC(cipherText, iv);
            for (byte b : plainText) {
                if (b < 0)  throw  new Challenge27OracleException(plainText);
            }
            return  new String(plainText).contains(EXPECTED_PARAM);
        }
    }

    static byte[]  breakChallenge27Oracle(Set2 decryptor, Challenge27Oracle challenge27Oracle) throws BadPaddingException {
        // Now the actual challenge, which it to mount a CCA attack using the oracle to ensure that
        // we get a piece of crafted cipher text that forces the oracle to return true.
        // The left pad that 'challenge16Encrypt' prepends is 32 bytes long. So the piece of text
        // we control occupies the whole second block and possibly beyond.
        // The desired string we want to inject into the cipher text ";admin=true;" is 12 bytes long.
        String   craftedString = "\0admin\0true\0";
        byte[]   cipherText = challenge27Oracle.apply(craftedString),  craftedCipherText = cipherText.clone();
        int   blockSize = decryptor.cipher.getBlockSize();

        assert  cipherText.length < blockSize * 3;

        // Now let's do the following CCA manipulation C_1, C_2, C_3 -> C_1, 0, C_1
        Arrays.fill(craftedCipherText, blockSize, 2 * blockSize, (byte) 0);
        System.arraycopy(cipherText, 0, craftedCipherText, blockSize << 1, blockSize);
        try {
            challenge27Oracle.isExpectedParamPresent(craftedCipherText, decryptor);
        } catch (Challenge27OracleException e) {
            return  Set1.challenge2(Arrays.copyOf(e.getPlainText(), blockSize),
                        Arrays.copyOfRange(e.getPlainText(), blockSize << 1, blockSize * 3));
        }
        return  new byte[0];
    }

    /**
     * @param message message to pad according to the MD padding scheme
     * @param order  byte order should be {@link ByteOrder#BIG_ENDIAN} for SHA and {@link ByteOrder#LITTLE_ENDIAN} for MD4
     */
    static byte[]  mdPad(byte message[], ByteOrder order) {
        int   lenMod64 = message.length & 0x3f;
        int   lenPadding = lenMod64 < 56  ?  56 - lenMod64 : 120 - lenMod64,  len = message.length + lenPadding + 8;
        ByteBuffer   bb = ByteBuffer.allocate(len);
        bb.put(message);
        bb.put((byte) 0x80);
        bb.put(new byte[lenPadding - 1]);
        bb.order(order).putLong(message.length << 3);
        return  bb.array();
    }

    @Data
    static class  ExistentialForgeryPair  {
        private final byte[]   forgedMessage,  forgedMAC;
    }

    static ExistentialForgeryPair  breakSHA1KeyedMAC(Set4 encryptor, byte message[], byte extension[]) {
        byte[]   origMac = encryptor.keyedMac(message);
        int[]   state = new int[5];
        SHA1.squashBytesToInts(origMac, 0, state, 0, 5);

        // Since we don't know the length of the key, let's assume it is not longer than 32 bytes
        for (int i=1; i <= 32; i++) {
            byte[]   prefixedMessage = new byte[i + message.length];
            Arrays.fill(prefixedMessage, 0, i, (byte) 0x20);
            System.arraycopy(message, 0, prefixedMessage, i, message.length);
            byte[] paddedMessage = mdPad(prefixedMessage, ByteOrder.BIG_ENDIAN),  forgedMessage,  forgedMAC;
            SHA1  h = new SHA1();
            h.engineUpdate(extension, 0, extension.length, state, paddedMessage.length);
            forgedMessage = Arrays.copyOf(Arrays.copyOfRange(paddedMessage, i, paddedMessage.length),
                    paddedMessage.length - i + extension.length);
            System.arraycopy(extension, 0, forgedMessage, paddedMessage.length - i, extension.length);
            forgedMAC = h.engineDigest();
            if (Arrays.equals(forgedMAC, encryptor.keyedMac(forgedMessage))) {
                return  new ExistentialForgeryPair(forgedMessage, forgedMAC);
            }
        }
        return  null;
    }

    static ExistentialForgeryPair  breakMD4KeyedMAC(Set4 encryptor, byte message[], byte extension[]) {
        byte[]   origMac = encryptor.keyedMacMD4(message);
        int[]    state = new int[4];
        MD4Ext.squashBytesToIntsLittle(origMac, 0, state, 0, 4);

        // Since we don't know the length of the key, let's assume it is not longer than 32 bytes
        for (int i=1; i <= 32; i++) {
            byte[]   prefixedMessage = new byte[i + message.length];
            Arrays.fill(prefixedMessage, 0, i, (byte) 0x20);
            System.arraycopy(message, 0, prefixedMessage, i, message.length);
            byte[] paddedMessage = mdPad(prefixedMessage, ByteOrder.LITTLE_ENDIAN),  forgedMessage,  forgedMAC;
            MD4Ext h = new MD4Ext();
            h.engineUpdate(extension, 0, extension.length, state, paddedMessage.length);
            forgedMessage = Arrays.copyOf(Arrays.copyOfRange(paddedMessage, i, paddedMessage.length),
                    paddedMessage.length - i + extension.length);
            System.arraycopy(extension, 0, forgedMessage, paddedMessage.length - i, extension.length);
            forgedMAC = h.engineDigest();
            if (Arrays.equals(forgedMAC, encryptor.keyedMacMD4(forgedMessage))) {
                return  new ExistentialForgeryPair(forgedMessage, forgedMAC);
            }
        }
        return  null;
    }

    static class  Challenge31Oracle implements BiPredicate<byte[], byte[]> {
        private static final String   TARGET = "http://localhost:8080/test?";

        @Override
        public boolean test(byte[] file, byte[] signature) {
            StringBuilder   qs = new StringBuilder();
            qs.append("file=").append(new String(file)).append("&signature=")
                    .append(DatatypeConverter.printHexBinary(signature));
            try {
                HttpURLConnection httpCon = (HttpURLConnection) new URL(TARGET + qs).openConnection();
                return  httpCon.getResponseCode() == HttpURLConnection.HTTP_OK;
            } catch (IOException e) {
                return  false;
            }
        }
    }

    static byte[]  breakeChallenge31Oracle(String fileName, Challenge31Oracle oracle) {
        final int   tries = 10;
        byte[]   file = fileName.getBytes(), signature = new byte[HMAC_SIGNATURE_LENGTH];
        LongUnaryOperator  op = x -> {
            long  t0 = System.nanoTime();
            oracle.test(file, signature);
            return  System.nanoTime() - t0;
        };

        for (int i=0; i < signature.length; i++) {
            int   j;
//            byte   b = 0;

            NEXT_BYTE:
            do {
                double baseline = LongStream.range(0, tries).map(op).average().orElseThrow(IllegalStateException::new);

                for (j = 0; j < 256; j++) {
                    signature[i] = (byte) j;

                    if (i == signature.length - 1) {
                        if (oracle.test(file, signature)) return signature;
                    }
                    double avg = LongStream.range(0, tries).map(op).average().orElseThrow(IllegalStateException::new);
                    if (avg - baseline > DELAY_MILLIS * 88e4) {
                        System.out.println("Guessed " + (i + 1) + " signature bytes");
                        break  NEXT_BYTE;
                    }
                }
//                b ^= 1;
//                signature[i] = b;
            } while (j == 256);    // No luck, we need to try again.

        }
        return  null;
    }

    public static void main(String[] args) {

        try {
            // Import DST Root CA X3 certificate into $JAVA_HOME/jre/lib/security/cacerts or uncomment the next line
            // Set1.suppressSSLServerCertificateChecks();

            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
            SecretKey key = aesKeyGen.generateKey();
            Set4   encryptor = new Set4(Cipher.ENCRYPT_MODE, key);
            Set2   decryptor = new Set2(Cipher.DECRYPT_MODE, key);

            System.out.println("Challenge 25");
            byte[]  unknownPlainText = challenge7("https://cryptopals.com/static/challenge-data/7.txt"),
                    cipherText = encryptor.cipherCTR(unknownPlainText),
                    recoveredPlainText = breakChallenge25Oracle(cipherText, encryptor.new Challenge25Oracle());
            System.out.println("Recovered plain text:\n" + new String(recoveredPlainText));

            System.out.println("\nChallenge 26");
            long   nonce = 1234567890;
            Challenge26Oracle challenge26Oracle = encryptor.new Challenge26Oracle(
                    Set2.CHALLANGE_16_QUERY_STRING_PREFIX.getBytes(),
                    Set2.CHALLANGE_16_QUERY_STRING_SUFFIX.getBytes(), nonce);
            breakChallenge26Oracle(challenge26Oracle);

            System.out.println("\nChallenge 27");
            Challenge27Oracle challenge27Oracle = encryptor.new Challenge27Oracle(
                    Set2.CHALLANGE_16_QUERY_STRING_PREFIX.getBytes(),
                    Set2.CHALLANGE_16_QUERY_STRING_SUFFIX.getBytes());
            byte   k[] = breakChallenge27Oracle(decryptor, challenge27Oracle);
            System.out.println("Recovered key: " + DatatypeConverter.printHexBinary(k));
            System.out.println("Original key: " + DatatypeConverter.printHexBinary(key.getEncoded()));
            System.out.println("Are these keys equal? " + new SecretKeySpec(k, 0, k.length, "AES").equals(key));

            System.out.println("\nChallenge 29");
            ExistentialForgeryPair existForgery = breakSHA1KeyedMAC(encryptor, CHALLANGE_29_ORIGINAL_MESSAGE.getBytes(),
                                                                               CHALLANGE_29_EXTENSION.getBytes());
            System.out.printf("Forged message: %s%nForged MAC: %s%nActual MAC: %s%n",
                    new String(existForgery.getForgedMessage()),
                    DatatypeConverter.printHexBinary(existForgery.getForgedMAC()),
                    DatatypeConverter.printHexBinary(encryptor.keyedMac(existForgery.getForgedMessage())) );

            System.out.println("\nChallenge 30");
            existForgery = breakMD4KeyedMAC(encryptor, CHALLANGE_29_ORIGINAL_MESSAGE.getBytes(),
                                                       CHALLANGE_29_EXTENSION.getBytes());
            System.out.printf("Forged message: %s%nForged MAC: %s%nActual MAC: %s%n",
                    new String(existForgery.getForgedMessage()),
                    DatatypeConverter.printHexBinary(existForgery.getForgedMAC()),
                    DatatypeConverter.printHexBinary(encryptor.keyedMacMD4(existForgery.getForgedMessage())) );

            System.out.println("\nChallenge 31");
            String   fileName = "foobardoo";
            k = breakeChallenge31Oracle(fileName, new Challenge31Oracle());
            System.out.printf("The matching HMAC signature for query parameter 'file=%s' is: %s%n",
                    fileName, DatatypeConverter.printHexBinary(k));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
