package com.cryptopals.set_5;

import lombok.SneakyThrows;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;

public class DiffieHellmanService extends UnicastRemoteObject implements DiffieHellman {
    private DiffieHellmanHelper df;
    private final Cipher   cipher;
    private SecretKeySpec   symKey;

    @SneakyThrows
    public DiffieHellmanService() throws RemoteException {
        super();
        cipher = Cipher.getInstance(DiffieHellmanHelper.AES_TRANSFORMATION);
    }

    @Override
    @SneakyThrows
    public BigInteger initiate(BigInteger p, BigInteger g, BigInteger A) {
        BigInteger   b;
        synchronized (cipher) {
            df = new DiffieHellmanHelper(p, g);
            b = df.generateExp();
            symKey = df.generateSymmetricKey(A, b);
        }
        return g.modPow(b, df.getModulus());
    }

    @Override
    public byte[] echo(byte[] cipherText) {
        byte[]   iv = Arrays.copyOf(cipherText, 16),  msg;

        synchronized (cipher) {
            try {
                cipher.init(Cipher.DECRYPT_MODE, symKey, new IvParameterSpec(iv));
                msg = cipher.doFinal(Arrays.copyOfRange(cipherText, 16, cipherText.length));
                System.out.printf("%nReceived message '%s'%n", new String(msg));
                IvParameterSpec iv2 = df.getFreshIV();
                cipher.init(Cipher.ENCRYPT_MODE, symKey, iv2);
                cipherText = cipher.doFinal(msg);
                msg = Arrays.copyOf(iv2.getIV(), iv2.getIV().length + cipherText.length);
                System.arraycopy(cipherText, 0, msg, iv2.getIV().length, cipherText.length);
                return  msg;
            } catch (InvalidKeyException | InvalidAlgorithmParameterException
                    | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
        return new byte[0];
    }
}
