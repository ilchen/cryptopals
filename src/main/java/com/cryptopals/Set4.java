package com.cryptopals;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


import static com.cryptopals.Set1.challenge7;

/**
 * Created by Andrei Ilchenko on 21-01-19.
 */
public class Set4 extends Set3 {

    Set4(int mode, SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        super(mode, key);
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

    public static void main(String[] args) {

        try {
            // Import DST Root CA X3 certificate into $JAVA_HOME/jre/lib/security/cacerts or uncomment the next line
            // Set1.suppressSSLServerCertificateChecks();

            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
            SecretKey key = aesKeyGen.generateKey();
            Set4   encryptor = new Set4(Cipher.ENCRYPT_MODE, key);

            System.out.println("Challenge 25");
            byte[]  unknownPlainText = challenge7("https://cryptopals.com/static/challenge-data/7.txt"),
                    cipherText = encryptor.cipherCTR(unknownPlainText),
                    recoveredPlainText = breakChallenge25Oracle(cipherText, encryptor.new Challenge25Oracle());
            System.out.println("Recovered plain text:\n" + new String(recoveredPlainText));


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
