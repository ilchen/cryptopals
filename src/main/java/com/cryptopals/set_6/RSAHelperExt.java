package com.cryptopals.set_6;

import com.cryptopals.set_5.RSAHelper;
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
        private String   name;
        private byte     asn1[];

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

    private Set<ByteBuffer>   processed = ConcurrentHashMap.newKeySet();
    public RSAHelperExt() {
        super();
    }
    public RSAHelperExt(BigInteger e) {
        super(e);
    }

    @SneakyThrows
    public BigInteger  decrypt(BigInteger cipherTxt) {
        MessageDigest  sha = MessageDigest.getInstance("SHA-1");
        return  processed.add(ByteBuffer.wrap(sha.digest(cipherTxt.toByteArray())))  ?  cipherTxt.modPow(d, n)
                                                                                     :  BigInteger.ZERO;
    }

    public boolean  decryptionOracle(BigInteger cipherTxt) {
        byte   repr[] = cipherTxt.modPow(d, n).toByteArray();
        return  (repr[repr.length - 1] & 0x01) == 0;
    }

    @SneakyThrows
    public BigInteger  sign(byte msg[], HashMethod hMethod) {
        final int   MIN_PAD = 3;   // \x00\x01\xff...xff\x00"
        MessageDigest   md = MessageDigest.getInstance(hMethod.name);
        byte[]   hash = md.digest(msg),  paddedMsg;
        int      lenPad = n.bitLength() / 8 - (hash.length + hMethod.asn1.length + MIN_PAD + 1);
        paddedMsg = new byte[lenPad + hash.length + hMethod.asn1.length + MIN_PAD];
        paddedMsg[1] = 1;
        Arrays.fill(paddedMsg, MIN_PAD - 1, MIN_PAD - 1 + lenPad, (byte) 0xff);
        System.arraycopy(hMethod.asn1, 0, paddedMsg, MIN_PAD + lenPad, hMethod.asn1.length);
        System.arraycopy(hash, 0, paddedMsg, MIN_PAD + lenPad + hMethod.asn1.length, hash.length);
        return  new BigInteger(paddedMsg).modPow(d, n);
    }

    @SneakyThrows
    public boolean  verify(byte msg[], BigInteger signature) {
        byte[]  paddedMsg = signature.modPow(e, n).toByteArray(),  hash;
        // BigInteger removed the most significant 0 from the padding
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
