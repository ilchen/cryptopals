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
    private static final int   BLOCK_SIZE = 16;
    private static final BigInteger   TWO_POW_128 = BigInteger.ONE.shiftLeft(128);
    private static final PolynomialGaloisFieldOverGF2   GF = new PolynomialGaloisFieldOverGF2(ONE.shiftLeft(128).or(valueOf(135)));
    private final PolynomialGaloisFieldOverGF2.FieldElement   h;
    private final int   tagLen;

    public GCM(SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this(key, 128);
    }

    /**
     * @param key  the key to use for the counter mode encryption and for the derivation of the authentication key
     * @param tLen  the authentication tag length in bits
     */
    public GCM(SecretKey key, int tLen) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        super(Cipher.ENCRYPT_MODE, key);
        if (tLen < 32  ||  tLen > 128  ||  (tLen & 0x07) != 0)
            throw  new IllegalArgumentException("Tag length not correct: " + tLen);
        tagLen = tLen;
        h = toFE(cipher.doFinal(new byte[16]));
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
                plainText.length + (tagLen >> 3));
        System.arraycopy(res, 0, buf, assocDataPaddedLen, plainText.length);

        // -then-MAC
        s = cipher.doFinal(nonceBuf.array());
        PolynomialGaloisFieldOverGF2.FieldElement   ss = toFE(cipher.doFinal(nonceBuf.array())),
                g = IntStream.range(0, buf.length / bSize)
                    .mapToObj(i -> toFE( Arrays.copyOfRange(buf, i * bSize, (i+1) * bSize)) )
                    .reduce(GF.getAdditiveIdentity(), (accu, elem) -> accu.add(elem).multiply(h));

        System.arraycopy(ss.add(g).asArray(), 0, res, plainText.length, tagLen >> 3);
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
        int    bSize = cipher.getBlockSize(),  plainTextLen = cipherText.length - (tagLen >> 3);
        byte[]   buf = prepareBuffer(cipherText, assocData, false, tagLen),  res,  tag;

        ByteBuffer nonceBuf = ByteBuffer.allocate(bSize).order(ByteOrder.BIG_ENDIAN).put(nonce).order(ByteOrder.BIG_ENDIAN).putInt(1);

        // Decrypt
        res = cipherCTR(Arrays.copyOf(cipherText, plainTextLen), new BigInteger(nonceBuf.array()).add(ONE).toByteArray());

        // Check the MAC
        PolynomialGaloisFieldOverGF2.FieldElement   ss = toFE(cipher.doFinal(nonceBuf.array())),
                g = IntStream.range(0, buf.length / bSize)
                        .mapToObj(i -> toFE( Arrays.copyOfRange(buf, i * bSize, (i+1) * bSize)) )
                        .reduce(GF.getAdditiveIdentity(), (accu, elem) -> accu.add(elem).multiply(h));

//        g2 = GF.getAdditiveIdentity();
//        for (int i=0; i < buf.length / bSize; i++) {
//            g2 = g2.add(toFE( Arrays.copyOfRange(buf, i * bSize, (i+1) * bSize)));
//            g2 = g2.multiply(h);
//        }

        tag = ss.add(g).asArray();
        return  Arrays.equals(Arrays.copyOfRange(cipherText, plainTextLen, cipherText.length),
                              tagLen >> 3 == bSize  ?  tag : Arrays.copyOf(tag, tagLen >> 3))  ?  res : null;
    }

    /**
     * Calculates the summand of the GHASH that corresponds to the power of 2 ciphertext block differences between
     * the original ciphertext blocks and the forged ones.
     */
    public PolynomialGaloisFieldOverGF2.FieldElement  ghashPower2BlocksDifferences(
            PolynomialGaloisFieldOverGF2.FieldElement[] coeffs,
            PolynomialGaloisFieldOverGF2.FieldElement[] forgedCoeffs)  {

        PolynomialGaloisFieldOverGF2.FieldElement   d,  g = GF.getAdditiveIdentity();

        for (int i=0; i < coeffs.length; i++) {
            d = coeffs[i].subtract(forgedCoeffs[i]);
            d = d.multiply(h.scale(ONE.shiftLeft(i+1)));
            g = g.add(d);
        }

        return  g;
    }

    /**
     * @return  the authentication key of the one-time-MAC
     */
    public PolynomialGaloisFieldOverGF2.FieldElement  getAuthenticationKey() {
        return  h;
    }

    /**
     * Prepares a buffer over which GHASH will be calculated if {@code includeTag==false}, otherwise returns
     * the buffer over which GHASH was calculated appended with the actual GHASH tag
     * @param cipherText  byte array representing GCM ciphertext
     * @param assocData  byte array representing associated data
     * @param includeTag  indicates whether the last block of cipher text, which represents a GHASH tag, must be
     *                    copied as the last block of the array returned
     * @param tLen  GHASH tag length in bits
     */
    private static byte[]  prepareBuffer(byte[] cipherText, byte[] assocData, boolean includeTag, int tLen) {
        int    plainTextLen = cipherText.length - (tLen >> 3),
                assocDataPaddedLen = (assocData.length / BLOCK_SIZE + (assocData.length % BLOCK_SIZE != 0  ?  1 : 0)) * BLOCK_SIZE,
                plainTextPaddedLen = (plainTextLen / BLOCK_SIZE + (plainTextLen % BLOCK_SIZE != 0  ?  1 : 0)) * BLOCK_SIZE;
        byte[]   buf = new byte[assocDataPaddedLen + plainTextPaddedLen + BLOCK_SIZE + (includeTag ? BLOCK_SIZE : 0)],  res,  s;
        System.arraycopy(assocData, 0, buf, 0, assocData.length);
        System.arraycopy(cipherText, 0, buf, assocDataPaddedLen, plainTextLen);
        ByteBuffer nonceBuf = ByteBuffer.allocate(BLOCK_SIZE).order(ByteOrder.BIG_ENDIAN)
                .putLong(assocData.length * Byte.SIZE).putLong(plainTextLen * Byte.SIZE);
        System.arraycopy(nonceBuf.array(), 0, buf, assocDataPaddedLen + plainTextPaddedLen, BLOCK_SIZE);
        if (includeTag) {
            System.arraycopy(cipherText, plainTextLen, buf, assocDataPaddedLen + plainTextPaddedLen + BLOCK_SIZE, BLOCK_SIZE);
        }
        return  buf;
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
     * Extracts all blocks of the ciphertext that are the coefficients of x<sup>2^i</sup> (where i = 1, 2, ..., n)
     * in the polynomial in the indeterminate x over GF(2<sup>128</sup>).
     * @return the coefficients of x<sup>2</sup>, x<sup>4</sup>, x<sup>8</sup>, etc. The coefficient of x is not
     * returned since it represents the length of the plain text and associated data and is not practical for the
     * purposes of the attack outlined in the
     * <a href="https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf">
     *     Authentication weaknesses in GCM</a> paper. The first coefficient returned by this method is that of x<sup>2</sup>.
     */
    public static PolynomialGaloisFieldOverGF2.FieldElement[]  extractPowerOf2Blocks(byte[] cipherText, int plnTextLen) {
        assert plnTextLen < cipherText.length;
        int   n = 31 - Integer.numberOfLeadingZeros(plnTextLen >> 4);
        //System.out.printf("Length: %d,  # blocks: %d,  # power 2 blocks: %d%n", plnTextLen, plnTextLen >> 4, n);
        PolynomialGaloisFieldOverGF2.FieldElement[]   ret = IntStream.range(1, n+1)
                .mapToObj(i -> {
                    int  low = plnTextLen - ((1 << i) - 1) * BLOCK_SIZE;
                    //System.out.printf("[%d, %d]", low, low+BLOCK_SIZE);
                    return  toFE( Arrays.copyOfRange(cipherText, low, low + BLOCK_SIZE));
                }).toArray(PolynomialGaloisFieldOverGF2.FieldElement[]::new);
        //System.out.println();
        return  ret;
    }

    public static byte[]  replacePowerOf2Blocks(byte[] cipherText, int plnTextLen,
                                                PolynomialGaloisFieldOverGF2.FieldElement[] coeffs) {
        assert plnTextLen < cipherText.length;
        int   n = 31 - Integer.numberOfLeadingZeros(plnTextLen >> 4),  low;
        byte[]  ret = cipherText.clone();
        //System.out.printf("Length: %d,  # blocks: %d,  # power 2 blocks: %d%n", plnTextLen, plnTextLen >> 4, n);
        for (int i=1; i <= n; i++) {
            low = plnTextLen - ((1 << i) - 1) * BLOCK_SIZE;
            //System.out.printf("[%d, %d]", low, low+BLOCK_SIZE);
            System.arraycopy(coeffs[i-1].asArray(), 0, ret, low, BLOCK_SIZE);
        }
        //System.out.println();
        return  ret;
    }

    /**
     * Converts ciphertext and associated data into a polynomial ring over GF(2<sup>128</sup>).
     * @return  a polynomial ring whose x^0 coefficient is the last 16 byte block in {@code buf}, and the highest
     *          term coefficient is the first.
     */
    public static PolynomialRing2<PolynomialGaloisFieldOverGF2.FieldElement>  toPolynomialRing2(byte[] cipherText, byte[] assocData) {
        byte[]   buf = prepareBuffer(cipherText, assocData, true, 16 * 8);
        int      last = buf.length / BLOCK_SIZE;
        return  new PolynomialRing2<>(IntStream.range(0, last)
                .mapToObj(i -> toFE( Arrays.copyOfRange(buf, (last - i - 1) * BLOCK_SIZE, (last - i) * BLOCK_SIZE)) )
                .toArray(PolynomialGaloisFieldOverGF2.FieldElement[]::new));
    }

    /**
     * Forges valid cipher text from legit cipher text and associated data coupled with a recovered authentication key.
     * @param additionalBogusAssocData  blocksize-long buffer, must be the same size as padded {@code legitAssocData}
     */
    public static byte[]  forgeCipherText(byte[] legitCipherText, byte[] legitAssocData, byte[] additionalBogusAssocData,
                                          PolynomialGaloisFieldOverGF2.FieldElement authenticationKey) {
        int    plainTextLen = legitCipherText.length - BLOCK_SIZE,
               assocDataPaddedLen = (legitAssocData.length / BLOCK_SIZE + (legitAssocData.length % BLOCK_SIZE != 0  ?  1 : 0)) * BLOCK_SIZE,
               plainTextPaddedLen = (plainTextLen / BLOCK_SIZE + (plainTextLen % BLOCK_SIZE != 0  ?  1 : 0)) * BLOCK_SIZE,
               lastPower = plainTextPaddedLen / BLOCK_SIZE + 1,
               last = additionalBogusAssocData.length / BLOCK_SIZE;

        if (additionalBogusAssocData.length != assocDataPaddedLen) {
            throw new IllegalArgumentException("additionalBogusAssocData must be of same length as padded legit associated data and not "
                                               + additionalBogusAssocData.length);
        }

        // We start with the original legit tag...
        PolynomialGaloisFieldOverGF2.FieldElement   forgedTag = toFE(Arrays.copyOfRange(
                legitCipherText, legitCipherText.length - BLOCK_SIZE, legitCipherText.length));

        byte[]   buf = new byte[assocDataPaddedLen];
        System.arraycopy(legitAssocData, 0, buf, 0, legitAssocData.length);

        // ... and then subtract from it the legit associated data and
        //     add to it bogus associated data.
        for (int i=last; i > 0; i-=1) {
            lastPower++;

            // Remove the summand of the legit associated data
            forgedTag = forgedTag.subtract(
                    toFE( Arrays.copyOfRange(legitAssocData, (last - 1) * BLOCK_SIZE, last * BLOCK_SIZE))
                            .multiply(authenticationKey.scale(valueOf(lastPower))) );

            // And then add the summand of the bogus associate data
            forgedTag = forgedTag.add(
                    toFE( Arrays.copyOfRange(additionalBogusAssocData, (last - 1) * BLOCK_SIZE, last * BLOCK_SIZE))
                        .multiply(authenticationKey.scale(valueOf(lastPower))) );
        }
        byte[]  res = legitCipherText.clone();
        System.arraycopy(forgedTag.asArray(), 0, res, legitCipherText.length - BLOCK_SIZE, BLOCK_SIZE);
        return  res;
    }
}
