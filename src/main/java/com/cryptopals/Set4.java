package com.cryptopals;

import lombok.Data;
import sun.security.provider.MD4;
import sun.security.provider.MD4Ext;
import sun.security.provider.SHA1;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static com.cryptopals.Set1.challenge7;

/**
 * Created by Andrei Ilchenko on 21-01-19.
 */
public class Set4 extends Set3 {
    static final String   CHALLANGE_29_ORIGINAL_MESSAGE = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",
                          CHALLANGE_29_EXTENSION = ";admin=true";
    private static final int   SHA_BLOCKSIZE = 64;
    private SecretKey  key;
    private MessageDigest   sha,  md4;

    Set4(int mode, SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
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

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
