package com.cryptopals.set_5;

import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

@Component
public class DiffieHellmanMITMService implements DiffieHellman {
    private DiffieHellman   server;
    private Cipher   cipher;
    //private BigInteger A,  B,  modulus;
    private SecretKeySpec   symKey;


    public DiffieHellmanMITMService() throws RemoteException, NotBoundException, MalformedURLException,
                                             NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance(DiffieHellmanHelper.AES_TRANSFORMATION);
        symKey = new SecretKeySpec(
                Arrays.copyOf(MessageDigest.getInstance("SHA-1").digest(new byte[1]), 16), "AES");
        String serviceUrl = "rmi://localhost/DiffieHellmanService";
        server = (DiffieHellman) Naming.lookup(serviceUrl);
    }

    @Override
    public BigInteger initiate(BigInteger p, BigInteger g, BigInteger A) throws RemoteException {
//        modulus = p;
//        this.A = A;
        server.initiate(p, g, p);
        return  p;
    }

    @Override
    public byte[] echo(byte[] cipherText) throws RemoteException {
        byte[]   iv = Arrays.copyOf(cipherText, 16),  msg;

        synchronized (cipher) {
            try {
                cipher.init(Cipher.DECRYPT_MODE, symKey, new IvParameterSpec(iv));
                msg = cipher.doFinal(Arrays.copyOfRange(cipherText, 16, cipherText.length));
                System.out.printf("%n-> '%s'%n", new String(msg));
                cipherText = server.echo(cipherText);
                iv = Arrays.copyOf(cipherText, 16);
                cipher.init(Cipher.DECRYPT_MODE, symKey, new IvParameterSpec(iv));
                msg = cipher.doFinal(Arrays.copyOfRange(cipherText, 16, cipherText.length));
                System.out.printf("%n<- '%s'%n", new String(msg));
                return  cipherText;
            } catch (InvalidKeyException | InvalidAlgorithmParameterException
                    | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
        return new byte[0];
    }
}
