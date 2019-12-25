package com.cryptopals.set_8;

import com.cryptopals.Set3;

import javax.crypto.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.IntStream;

import static java.math.BigInteger.*;

/**
 * Implements Galois Counter Mode (GCM) in accordance with the
 * <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf">NIST recommendations.</a>
 */
public class GCM extends Set3 {
    private static final BigInteger   TWO_POW_128 = BigInteger.ONE.shiftLeft(128);
    private static final PolynomialGaloisFieldOverGF2   GF = new PolynomialGaloisFieldOverGF2(ONE.shiftLeft(128).or(valueOf(135)));
    private final PolynomialGaloisFieldOverGF2.FieldElement   h;

    public GCM(SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        super(Cipher.ENCRYPT_MODE, key);
        byte[]   tmp = cipher.doFinal(new byte[16]);
        h = toFE(/*new BigInteger(*/cipher.doFinal(new byte[16]));
    }

    /**
     * Encrypts {@code plainText} in the GCM mode using {@code nonce} as the counter.
     * @param plainText  plain text to encrypt
     * @param assocData  associated data that will be used in calculating the GMAC
     * @param nonce  a nonce used both during encrypting in the CTR mode as well as when calculating the GMAC
     * @return  cipher text corresponding to the plain text. The last block of the cipher text is the GMAC calculated
     *          over <code>a0 || a1 || c0 || c1 || c2 || len(AD) || len(C)</code>.
     */
    public byte[]  cipher(byte[] plainText, byte[] assocData, byte[] nonce) throws BadPaddingException, IllegalBlockSizeException {
        if (nonce.length != 12)  throw  new IllegalArgumentException("Nonce is not 12 bytes but " + nonce.length);
        int    bSize = cipher.getBlockSize(),
               assocDataPaddedLen = (assocData.length / bSize + (assocData.length % bSize != 0  ?  1 : 0)) * bSize,
               plainTextPaddedLen = (plainText.length / bSize + (plainText.length % bSize != 0  ?  1 : 0)) * bSize;
        byte[]   buf = new byte[assocDataPaddedLen + plainTextPaddedLen + bSize],  res,  s;
        System.arraycopy(assocData, 0, buf, 0, assocData.length);
        ByteBuffer nonceBuf = ByteBuffer.allocate(bSize).order(ByteOrder.BIG_ENDIAN)
                              .putLong(assocData.length * Byte.SIZE).putLong(plainText.length * Byte.SIZE);
        System.arraycopy(nonceBuf.array(), 0, buf, assocDataPaddedLen + plainTextPaddedLen, bSize);
        nonceBuf.clear();
        nonceBuf.put(nonce).order(ByteOrder.BIG_ENDIAN).putInt(1);

        // Encrypt-
        res = Arrays.copyOf(cipherCTR(plainText, new BigInteger(nonceBuf.array()).add(ONE).toByteArray()),
                plainText.length + bSize );
        System.arraycopy(res, 0, buf, assocDataPaddedLen, plainText.length);

        // -then-MAC
        s = cipher.doFinal(nonceBuf.array());
        PolynomialGaloisFieldOverGF2.FieldElement   ss = toFE(cipher.doFinal(nonceBuf.array())),
                g = IntStream.range(0, buf.length / bSize)
                    .mapToObj(i -> toFE( Arrays.copyOfRange(buf, i * bSize, (i+1) * bSize)) )
                    .reduce(GF.getAdditiveIdentity(), (accu, elem) -> accu.add(elem).multiply(h));

        System.arraycopy(ss.add(g).asArray(), 0, res, plainText.length, bSize);
        return  res;
    }

    /**
     * Decrypts {@code cipherText} in the GCM mode using {@code nonce} as the counter.
     * @param cipherText  cipher text to decrypt
     * @param assocData  associated data that will be used in calculating the GMAC
     * @param nonce  a nonce used both during decrypting in the CTR mode as well as when calculating the GMAC
     * @return  plain text corresponding to the cipher text or {@code null}, which represents &#8869;.
     */
    public byte[]  decipher(byte[] cipherText, byte[] assocData, byte[] nonce) throws BadPaddingException, IllegalBlockSizeException {
        if (nonce.length != 12)  throw  new IllegalArgumentException("Nonce is not 12 bytes but " + nonce.length);
        int    bSize = cipher.getBlockSize(),  plainTextLen = cipherText.length - bSize,
                assocDataPaddedLen = (assocData.length / bSize + (assocData.length % bSize != 0  ?  1 : 0)) * bSize,
                plainTextPaddedLen = (plainTextLen / bSize + (plainTextLen % bSize != 0  ?  1 : 0)) * bSize;
        byte[]   buf = new byte[assocDataPaddedLen + plainTextPaddedLen + bSize],  res,  s;
        System.arraycopy(assocData, 0, buf, 0, assocData.length);
        System.arraycopy(cipherText, 0, buf, assocDataPaddedLen, plainTextLen);
        ByteBuffer nonceBuf = ByteBuffer.allocate(bSize).order(ByteOrder.BIG_ENDIAN)
                .putLong(assocData.length * Byte.SIZE).putLong(plainTextLen * Byte.SIZE);
        System.arraycopy(nonceBuf.array(), 0, buf, assocDataPaddedLen + plainTextPaddedLen, bSize);

        nonceBuf.clear();
        nonceBuf.put(nonce).order(ByteOrder.BIG_ENDIAN).putInt(1);

        // Decrypt
        res = cipherCTR(Arrays.copyOf(cipherText, plainTextLen), new BigInteger(nonceBuf.array()).add(ONE).toByteArray());

        // Check the MAC
        s = cipher.doFinal(nonceBuf.array());
        PolynomialGaloisFieldOverGF2.FieldElement   ss = toFE(cipher.doFinal(nonceBuf.array())),
                g = IntStream.range(0, buf.length / bSize)
                        .mapToObj(i -> toFE( Arrays.copyOfRange(buf, i * bSize, (i+1) * bSize)) )
                        .reduce(GF.getAdditiveIdentity(), (accu, elem) -> accu.add(elem).multiply(h));

        return  Arrays.equals(Arrays.copyOfRange(cipherText, plainTextLen, cipherText.length), ss.add(g).asArray())
                    ? res : null;
    }

    /**
     * Reverses the bits in {@code polynomial} such that the leftmost bit becomes the rightmost bit, the one but
     * leftmost becomes the one but rightmost etc.
     */
    static byte[] reverseBits(byte[] polynomial) {
        ByteBuffer   long1 = ByteBuffer.allocate(8),  long2 = ByteBuffer.allocate(8),  res = ByteBuffer.allocate(16);
        long1.put(polynomial, 0, 4);
        long2.put(polynomial, 4, 8);
        long1.put(polynomial, 12, 4);
        long1.rewind();     long2.rewind();
        long   revLong1 = Long.reverse(long1.getLong()),  revLong2 = Long.reverse(long2.getLong());
        res.putInt((int) (revLong1 >>> 32));
        res.putLong(revLong2);
        res.putInt((int) revLong1);
        return  res.array();
    }

//    private static PolynomialGaloisFieldOverGF2.FieldElement  toFE(BigInteger polynomial) {
//        if (polynomial.signum() == -1)  {
//            polynomial = polynomial.add(TWO_POW_128);
//        }
//        return  GF.createElement(polynomial);
//    }

    /**
     * Converts a block into an element of GF(2^128)
     */
    private static PolynomialGaloisFieldOverGF2.FieldElement  toFE(byte[] buf) {
        byte[]   buf2 = reverseBits(buf);
        BigInteger   res = new BigInteger(buf2);
        PolynomialGaloisFieldOverGF2.FieldElement   r = GF.createElement((buf2[0] & 0x80) != 0  ?  res.add(TWO_POW_128) : res);
        assert  Arrays.equals(buf, r.asArray());
        return  r;
    }

    /**
     * Converts an array whose size is a multiple of 16 bytes into a polynomial ring over GF(2<sup>128</sup>).
     * @param buf  an array whose length must be a multiple of 16
     * @return  a polynomial ring whose x^0 coefficient is the last 16 byte block in {@code buf}, and the highest
     *          term coefficient is the first.
     */
    public static PolynomialRing<PolynomialGaloisFieldOverGF2.FieldElement>  toPolynomialRing(byte[] buf) {
        int bSize = 16,  last = buf.length / bSize;
        return  new PolynomialRing<>(IntStream.range(0, last)
                .mapToObj(i -> toFE( Arrays.copyOfRange(buf, (last - i - 1) * bSize, (last - i) * bSize)) )
                .toArray(PolynomialGaloisFieldOverGF2.FieldElement[]::new));
    }

}
