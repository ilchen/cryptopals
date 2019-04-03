package com.cryptopals.set_6;

import com.cryptopals.Set1;
import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

import static java.math.BigInteger.*;

/**
 * Created by Andrei Ilchenko on 30-03-19.
 */
public class DSAHelper {
    @Data
    public static class PublicKey {
        private final BigInteger  p,  q,  g,  y;

        @SneakyThrows
        public boolean   verifySignature(byte msg[], Signature signature) {
            MessageDigest   sha = MessageDigest.getInstance("SHA-1");
            BigInteger   w = signature.getS().modInverse(q),  u1 = fromHash(sha.digest(msg)).multiply(w).mod(q),
                         u2 = signature.getR().multiply(w).mod(q);
            return  g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q).equals(signature.getR());
        }
    }

    @Data
    public static class Signature {
        private final BigInteger  r,  s;
    }

    public static final BigInteger  P = new BigInteger("800000000000000089e1855218a0e7dac38136ffafa72eda7" +
            "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6" +
            "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe" +
            "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2" +
            "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16),
            Q = new BigInteger("f4f47f05794b256174bba6e9b396a7707e563c5b", 16),
            G = new BigInteger("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119" +
                    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5" +
                    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047" +
                    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892" +
                    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16),
            TWO = BigInteger.valueOf(2L);
    private static int   L = 1024,  QL = 160;
    private static final Random SECURE_RANDOM = new SecureRandom(); // Thread safe
    private final BigInteger   p,  q,  g,  x;

    public static BigInteger   fromHash(byte hash[]) {
        // BigInteger   h = new BigInteger(hash).add(ONE.shiftLeft(hash.length * 8));
        byte   prefixedHash[] = new byte[hash.length + 1];
        System.arraycopy(hash, 0, prefixedHash, 1, hash.length);
        return  new BigInteger(prefixedHash);
    }

    @SneakyThrows
    static BigInteger[]  findDSAPrimes() {
        MessageDigest   sha = MessageDigest.getInstance("SHA-1");
        BigInteger   s,  S,  p,  q,  N,  W,  X;
        byte   u[];
        int   n = (L - 1) / QL,  b = (L - 1) % QL;
        do {
            s = new BigInteger(QL*3, 2, SECURE_RANDOM);
            u = Set1.challenge2(sha.digest(s.toByteArray()),
                    sha.digest(s.add(ONE).mod(TWO.pow(s.bitLength())).toByteArray()));
            u[0] &= 0x7f;     u[19] |= 1;    // Big-endian
        } while (!(q = fromHash(u)).isProbablePrime(64));

        N = TWO;     S = s;
        do {
            final BigInteger  NN = N;
            W = IntStream.rangeClosed(0, n).mapToObj(k ->
                    new Object() {
                        BigInteger v = fromHash(
                                sha.digest(S.add(NN).add(BigInteger.valueOf(k)).mod(TWO.pow(S.bitLength())).toByteArray()));
                        int i = k;
                    }).map(pair -> TWO.pow(160 * pair.i).multiply(pair.i == n ? pair.v.mod(TWO.pow(b)) : pair.v))
                    .reduce(ZERO, BigInteger::add);
            X = W.add(TWO.pow(L - 1));
            p = X.subtract(X.mod(TWO.multiply(q)).subtract(ONE));
            N = N.add(BigInteger.valueOf(n)).add(ONE);
        } while (!p.isProbablePrime(64));
        return  new BigInteger[] {   p,  q   };
    }

    public DSAHelper() {
        this(findDSAPrimes());
    }

    public DSAHelper(BigInteger pq[]) {
        this(pq[0], pq[1]);
    }

    public DSAHelper(BigInteger p,  BigInteger q) {
        this(p, q, LongStream.iterate(2, x -> x+1).mapToObj(BigInteger::valueOf)
                .map(h -> h.modPow(p.subtract(ONE).divide(q), p))
                .filter(g -> g.compareTo(ONE) > 0).findFirst().orElseThrow(IllegalStateException::new));
    }

    public DSAHelper(BigInteger p,  BigInteger q,  BigInteger g) {
        this.p = p;     this.q = q;     this.g = g;
        x = generateK();
    }

    public DSAHelper(BigInteger p,  BigInteger q,  BigInteger g, BigInteger x) {
        this.p = p;     this.q = q;     this.g = g;
        this.x = x;
    }

    private BigInteger   generateK() {
        BigInteger   k;
        do {
            k = new BigInteger(q.bitLength(), SECURE_RANDOM);
        }  while (k.compareTo(ONE) <= 0  ||  k.compareTo(q) >= 0);
        return  k;
    }

    public PublicKey  getPublicKey() {
        return  new PublicKey(p, q, g, g.modPow(x, p));
    }

    @SneakyThrows
    public Signature  sign(byte msg[]) {
        MessageDigest   sha = MessageDigest.getInstance("SHA-1");
        BigInteger   k = generateK(),  r = g.modPow(k, p).mod(q);
        return  new Signature(r, k.modInverse(q).multiply(fromHash(sha.digest(msg)).add(x.multiply(r))).mod(q));
    }

}
