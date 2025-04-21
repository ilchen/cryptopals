package com.cryptopals.set_6;

import com.cryptopals.set_5.RSAHelper;
import com.squareup.jnagmp.Gmp;
import lombok.SneakyThrows;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RSAHelperExt extends RSAHelper {
    public enum HashMethod {
        MD5("MD5", new byte[] {   0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, (byte) 0x86,
                                     0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10   }),
        SHA1("SHA-1", new byte[] {   0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                                        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14   }),
        SHA256("SHA-256", new byte[] {   0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86,
                                            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20   });
        public final String   name;
        public final byte     asn1[];

        HashMethod(String n, byte asn1[]) {
            this.name = n;
            this.asn1 = asn1;
        }
        public byte[]  getASN1Encoding() {
            return  asn1;
        }
        @Override
        public String toString() {
            return name;
        }
    }


    private final Set<ByteBuffer>   processed = ConcurrentHashMap.newKeySet();
    private final int    numBytes = (n.bitLength() + 7 & ~7) / 8; /* Number of bytes required to store n.bitLength() bits */
    public RSAHelperExt() {
        super();
    }
    public RSAHelperExt(BigInteger e) {
        super(e);
    }
    public RSAHelperExt(BigInteger e, int numBits) {
        super(e, numBits);
    }
    public RSAHelperExt(BigInteger p, BigInteger q, BigInteger e) {
        super(p, q, e);
    }

    @Override
    public RSAHelper.PublicKey getPublicKey() {
        return  new PublicKey(super.getPublicKey().e(), n);
    }

    @SneakyThrows
    public BigInteger  decrypt(BigInteger cipherTxt) {
        MessageDigest  sha = MessageDigest.getInstance("SHA-1");
                                                                                      // cipherTxt.modPow(d, n)
        return  processed.add(ByteBuffer.wrap(sha.digest(cipherTxt.toByteArray())))  ?  Gmp.modPowInsecure(cipherTxt, d, n)
                                                                                     :  BigInteger.ZERO;
    }

    public boolean  decryptionOracle(BigInteger cipherTxt) {
        byte   repr[] = Gmp.modPowInsecure(cipherTxt, d, n).toByteArray();
        // byte   repr[] = cipherTxt.modPow(d, n).toByteArray();
        return  (repr[repr.length - 1] & 0x01) == 0;
    }

    public boolean  paddingOracle(BigInteger cipherTxt) {
        byte   repr[] = Gmp.modPowInsecure(cipherTxt, d, n).toByteArray();
        // byte   repr[] = cipherTxt.modPow(d, n).toByteArray();
        return  repr.length == numBytes - 1  &&  repr[0] == 2;
    }

    /**
     * Pads {@code plainText} using the PKCS#1 v1.5 padding mode 2 (encryption)
     * @param plainText  the message to pad
     * @param bitNum  the bit length of the RSA modulus
     * @return PKCS-padded plaintext with randomness added
     */
    public static BigInteger  pkcs15Pad(byte plainText[], int bitNum) {
        byte   pad[] = new byte[(bitNum + 7 & ~7) / 8];
        if (pad.length - plainText.length <= 11) // 00 02 at-least-8-bytes-of-randomness 00 message-bytes
            throw new  IllegalArgumentException("Plaintext too long to fit in the RSA modulus with PKCS padding");
        System.arraycopy(plainText, 0, pad, pad.length - plainText.length, plainText.length);
//        pad[pad.length - plainText.length - 1] = 0; // In Java arrays are zero-initialized
        pad[0] = 0;     pad[1] = 2;
        for (int i=2; i < pad.length - plainText.length - 1; i++) {
            while (0 == (pad[i] = (byte) SECURE_RANDOM.nextInt(256)) );
        }
        return  new BigInteger(pad);
    }

    public byte[]  pkcs15Unpad(BigInteger paddedPlainText) {
        byte   repr[] = paddedPlainText.toByteArray();
        // BigInteger removes the most significant 0 byte from the internal representation
        if (repr.length == numBytes - 1  && repr[0] == 2) {
            for (int i=1; i < repr.length; i++) {
                // EB1 = 00, EB2 = 02, EB3 through EB10 are nonzero. At least one of the bytes EB11 through EBk is 00.
                // EB11 is repr[9] given that BigInteger removes the most significant 0 byte.
                if (repr[i] == 0  &&  i >= 9)  {
                    return  Arrays.copyOfRange(repr, i + 1, repr.length);
                }
            }
        }
        throw  new IllegalArgumentException(paddedPlainText + " is not PKCS padded");
    }

    /**
     * Pads {@code msg} using the PKCS#1 v1.5 padding mode 1 (signing): <p>
     * <code>00h 01h ffh ffh ... ffh ffh 00h ASN.1 HASH</code></p>. The implementation is
     * in line with
     * <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-9.2">the EMSA-PKCS1-v1_5 specification</a>
     * except that I allow the PS part of the padding (consisting of the 0xff octets) to be shorter than 8 bytes.
     * @param msg  the message to pad
     * @param hMethod  one of { {@link HashMethod#MD5}, {@link HashMethod#SHA1}, {@link HashMethod#SHA256} }
     * @param bitLength  the bit length of the RSA modulus
     * @return  an PKCS1.5-padded message
     */
    @SneakyThrows
    public static BigInteger  pkcs15Pad(byte msg[], HashMethod hMethod, int bitLength) {
        final int   MIN_PAD = 3;   // \x00\x01\xff...xff\x00"
        MessageDigest   md = MessageDigest.getInstance(hMethod.name);
        byte[]   hash = md.digest(msg),  paddedMsg;
        int      lenPad = (bitLength + 7 & ~7) / 8 - (hash.length + hMethod.asn1.length + MIN_PAD + 1);
        // If the RSA modulus is k*8 bits long, we can pack up an extra byte in the padding.
        // This is because the leading 00 octet ensures that the padding block, converted to an integer,
        // is less than the modulus.
        if (bitLength % 8 == 0)  lenPad++;
        paddedMsg = new byte[lenPad + hash.length + hMethod.asn1.length + MIN_PAD];
        paddedMsg[1] = 1;
        Arrays.fill(paddedMsg, MIN_PAD - 1, MIN_PAD - 1 + lenPad, (byte) 0xff);
        System.arraycopy(hMethod.asn1, 0, paddedMsg, MIN_PAD + lenPad, hMethod.asn1.length);
        System.arraycopy(hash, 0, paddedMsg, MIN_PAD + lenPad + hMethod.asn1.length, hash.length);
        return  new BigInteger(paddedMsg);
    }

    @SneakyThrows
    public BigInteger  sign(byte msg[], HashMethod hMethod) {
        return  pkcs15Pad(msg, hMethod, n.bitLength()).modPow(d, n);
    }

    @SneakyThrows
    public boolean  verify(byte msg[], BigInteger signature) {
        byte[]  paddedMsg = getPublicKey().encrypt(signature).toByteArray(),  hash;
        // BigInteger removes the most significant 0 from the padding
        if (paddedMsg[0] != 1)  return  false;
        int   i = 1;
        while (i < paddedMsg.length  &&  paddedMsg[i] == (byte) 0xff)  i++;
        if (paddedMsg[i++] != 0)  return  false;
        for (HashMethod method : HashMethod.values()) {
            if (paddedMsg.length - i > method.asn1.length
                    &&  Arrays.equals(method.asn1, Arrays.copyOfRange(paddedMsg, i, i + method.asn1.length))) {
                MessageDigest   md = MessageDigest.getInstance(method.name);
                hash = md.digest(msg);
                return  paddedMsg.length - i - method.asn1.length >= hash.length
                        &&  Arrays.equals(hash, Arrays.copyOfRange(paddedMsg,
                        i + method.asn1.length, i + method.asn1.length + hash.length));
            }
        }
        return  false;
    }

}
