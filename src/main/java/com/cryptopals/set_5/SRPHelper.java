package com.cryptopals.set_5;

import lombok.SneakyThrows;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

public class SRPHelper extends DiffieHellmanHelper {
    public static final BigInteger   K = BigInteger.valueOf(3);

    final private BigInteger   k;
    public SRPHelper(BigInteger p, BigInteger g, BigInteger k) {
        super(p, g);
        this.k = k;
    }

    public BigInteger  getSRPParameter() {
        return  k;
    }

    public static byte[]  longAsBytes(long salt) {
        return  ByteBuffer.allocate(Long.BYTES).putLong(salt).array();
    }

    public long  getFreshSalt() {
        return  secRandGen.nextLong();
    }

    @SneakyThrows // SHA-256 is guaranteed to be available by the Java platform.
    public BigInteger generateVerifier(long salt, byte P[]) {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(longAsBytes(salt));
        return  g.modPow(new BigInteger(sha256.digest(P)), p);
    }

    BigInteger  generatePublicServerKey(BigInteger verifier, BigInteger exp) {
        return   k.multiply(verifier).add(g.modPow(exp, p)).mod(p);
    }

    @SneakyThrows // SHA-256 is guaranteed to be available by the Java platform.
    byte[]  generateKeyServer(BigInteger A, BigInteger B, BigInteger b, BigInteger verifier) {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(A.toByteArray());
        BigInteger   u = new BigInteger(sha256.digest(B.toByteArray())),
                     S = A.multiply(verifier.modPow(u, p)).modPow(b, p);
        return  sha256.digest(S.toByteArray());
    }

    @SneakyThrows // SHA-256 is guaranteed to be available by the Java platform.
    public byte[]  generateKeyClient(BigInteger A, SRPServerResponse resp, BigInteger a, byte P[]) {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        if (A.equals(BigInteger.ZERO)  ||  A.mod(p).equals(BigInteger.ZERO))  {  // Hack for Challenge 37
            return  sha256.digest(BigInteger.ZERO.toByteArray());
        }
        sha256.update(A.toByteArray());
        BigInteger   u = new BigInteger(sha256.digest(resp.B().toByteArray()));
        sha256.update(longAsBytes(resp.salt()));
        BigInteger   x = new BigInteger(sha256.digest(P)),
                     S = resp.B().subtract(k.multiply(g.modPow(x, p))).modPow(a.add(u.multiply(x)), p);
        return  sha256.digest(S.toByteArray());
    }

}
