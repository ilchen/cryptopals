package com.cryptopals;

import com.cryptopals.set_5.DiffieHellman;
import org.springframework.context.annotation.Bean;
import org.springframework.remoting.rmi.RmiProxyFactoryBean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static com.cryptopals.Set1.challenge7;

/**
 * Created by Andrei Ilchenko on 03-03-19.
 */
public class Set5 {
    public static final BigInteger   P = new BigInteger(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16),
        G =  BigInteger.valueOf(2);
    public static final String   AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int   NUM_BITS = 1024;
    private Random   secRandGen = new SecureRandom();
    private MessageDigest sha = MessageDigest.getInstance("SHA-1");
    private BigInteger   p,  g;

    public Set5() throws NoSuchAlgorithmException {
        p = new BigInteger(NUM_BITS, 64, secRandGen);
        do {  // We need to exclude the trivial subgroups
            g = new BigInteger(NUM_BITS, secRandGen).mod(p);
        } while (g.equals(BigInteger.ONE) || g.equals(p.subtract(BigInteger.ONE)));
    }

    public Set5(BigInteger p, BigInteger g) throws NoSuchAlgorithmException {
        this.p = p;
        this.g = g;
    }

    public BigInteger  getModulus() {
        return  p;
    }

    public BigInteger  generateExp() {
        BigInteger   exp;
        do {
            exp = new BigInteger(p.bitLength(), secRandGen).mod(p);
        } while (exp.equals(BigInteger.ZERO) || exp.equals(BigInteger.ONE)
                 ||  exp.equals(p.subtract(BigInteger.ONE)));
        return  exp;
    }

    public SecretKeySpec generateSymmetricKey(BigInteger A, BigInteger b) {
        return  new SecretKeySpec(Arrays.copyOf(sha.digest(A.modPow(b, p).toByteArray()), 16), "AES");
    }

    public IvParameterSpec  getFreshIV() {
        byte[] iv = new byte[16];
        secRandGen.nextBytes(iv); /* Generate a secure random IV */
        return  new IvParameterSpec(iv);
    }


    @Bean
    public RmiProxyFactoryBean dhService() {
        RmiProxyFactoryBean rmiProxy = new RmiProxyFactoryBean();
        rmiProxy.setServiceUrl("rmi://localhost/DiffieHellmanService");
        rmiProxy.setServiceInterface(DiffieHellman.class);
        return rmiProxy;
    }


    public static void main(String[] args) {

        try {

            System.out.println("Challenge 34");
            //String serviceUrl = "rmi://localhost/DiffieHellmanService";
            String serviceUrl = "rmi://localhost/DiffieHellmanMITMService";
            DiffieHellman server = (DiffieHellman) Naming.lookup(serviceUrl);
            Set5   dh = new Set5(P, G);
            BigInteger   a = dh.generateExp(),  A = G.modPow(a, P),  B = server.initiate(P, G, A);
            Cipher cipher = Cipher.getInstance(Set5.AES_TRANSFORMATION);
            IvParameterSpec   iv = dh.getFreshIV();
            SecretKey sk = dh.generateSymmetricKey(B, a);
            cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

            String   msg = "Hello, Server!";
            byte[]   cipherText = cipher.doFinal(msg.getBytes()),
                     prefixedCT = Arrays.copyOf(iv.getIV(), iv.getIV().length + cipherText.length);
            System.arraycopy(cipherText, 0, prefixedCT, iv.getIV().length, cipherText.length);
            cipherText = server.echo(prefixedCT);

            iv = new IvParameterSpec(Arrays.copyOf(cipherText, 16));
            cipher.init(Cipher.DECRYPT_MODE, sk, iv);
            System.out.printf("-> '%s'%n<- '%s'%n", msg,
                    new String(cipher.doFinal(Arrays.copyOfRange(cipherText, 16, cipherText.length))) );


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
