package com.cryptopals.set_5;

import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.ONE;


/**
 * Created by Andrei Ilchenko on 03-03-19.
 */
public class DiffieHellmanHelper {
    public static final BigInteger   P = new BigInteger(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16),
        G =  BigInteger.valueOf(2);
    static final String   AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int   NUM_BITS = 1024;
    final Random   secRandGen = new SecureRandom(); // SecureRandom is thread-safe
    final BigInteger   p,  g;

    public DiffieHellmanHelper() {
        p = new BigInteger(NUM_BITS, 64, secRandGen);
        BigInteger  gCand;
        do {  // We need to exclude the trivial subgroups
            gCand = new BigInteger(NUM_BITS, secRandGen).mod(p);
        } while (gCand.equals(ONE) || gCand.equals(p.subtract(ONE)));
        g = gCand;
    }

    public DiffieHellmanHelper(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
    }

    public byte[] encryptMessage(byte msg[], byte key[]) {
        return  encryptMessage(msg, new SecretKeySpec(key, "AES"));
    }

    @SneakyThrows // AES is guaranteed to be available by the Java platform.
    public byte[] encryptMessage(byte msg[], SecretKey sk) {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        IvParameterSpec iv = getFreshIV();
        cipher.init(Cipher.ENCRYPT_MODE, sk, iv);
        byte[]  cipherText = cipher.doFinal(msg),
                prefixedCT = Arrays.copyOf(iv.getIV(), iv.getIV().length + cipherText.length);
        System.arraycopy(cipherText, 0, prefixedCT, iv.getIV().length, cipherText.length);
        return  prefixedCT;
    }

    public static byte[] decryptMessage(byte cipherText[], byte key[]) {
        return  decryptMessage(cipherText, new SecretKeySpec(key, "AES"));
    }

    @SneakyThrows // AES is guaranteed to be available by the Java platform.
    public static byte[] decryptMessage(byte cipherText[], SecretKey sk) {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(Arrays.copyOf(cipherText, 16)));
        return  cipher.doFinal(cipherText, 16, cipherText.length - 16);
    }

    public BigInteger  getModulus() {
        return  p;
    }

    public BigInteger  getGenerator() {
        return  g;
    }

    public BigInteger  generateExp() {
        BigInteger   exp;
        do {
            exp = new BigInteger(p.bitLength(), secRandGen).mod(p);
        } while (exp.equals(ZERO) || exp.equals(ONE)
                 ||  exp.equals(p.subtract(ONE)));
        return  exp;
    }


    public SecretKeySpec generateSymmetricKey(BigInteger A, BigInteger b) {
        return  generateSymmetricKey(A, b, 20, "AES");
    }

    @SneakyThrows // SHA-1 is guaranteed to be available by the Java platform.
    public SecretKeySpec generateSymmetricKey(BigInteger A, BigInteger b, int len, String keyAlgorithm) {
        MessageDigest sha = MessageDigest.getInstance(len > 20  ?  "SHA-256" : "SHA-1");
        return  new SecretKeySpec(Arrays.copyOf(sha.digest(A.modPow(b, p).toByteArray()), len), keyAlgorithm);
    }

    IvParameterSpec  getFreshIV() {
        byte[] iv = new byte[16];
        secRandGen.nextBytes(iv); /* Generate a secure random IV */
        return  new IvParameterSpec(iv);
    }

    /**
     * Finds all factors of the quotient of p-1 and {@code factor} that are smaller than 2^16 (if any) and greater than 4.
     * @param factor  one known divisor of {@code p-1} to speed the process up
     */
    public List<BigInteger>  findSmallFactors(BigInteger factor) {
        BigInteger   pMin1 = p.subtract(ONE),  limit = BigInteger.valueOf(1 << 16),
                     r[] = pMin1.divideAndRemainder(factor);
        if (!r[1].equals((ZERO))) {
            throw  new IllegalArgumentException(factor + " is not a factor of " + pMin1);
        }

        List<BigInteger>   factors = IntStream.range(2, 1 << 16) /* Finding all divisors of r */
                .filter(i -> r[0].remainder(BigInteger.valueOf(i)).equals(ZERO))
                .boxed().map(BigInteger::valueOf).collect(Collectors.toCollection(ArrayList::new));

        for (int i=0; i < factors.size() - 1; i++) {          /* Getting rid of non-prime divisors */
            BigInteger   f = factors.get(i);
            for (int j=i+1; j < factors.size();) {
                if (factors.get(j).remainder(f).equals(ZERO)) {
                    factors.remove(j);
                } else  j++;
            }
        }

        return  factors;
    }

    /**
     * Finds a generator of group Zp* of required order
     * @param order  the order the generator must have
     * @return a generator satisfying the order given
     */
    public BigInteger  findGenerator(BigInteger order) {
        Random   rnd = new Random();
        BigInteger   otherOrder = p.subtract(ONE).divide(order),  h;
        do {
            h = new BigInteger(p.bitLength(), rnd).modPow(otherOrder, p);
        }  while (h.equals(ONE));
        return  h;
    }

}
