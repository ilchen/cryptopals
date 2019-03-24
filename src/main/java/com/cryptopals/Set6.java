package com.cryptopals;

import com.cryptopals.set_5.RSAHelper;
import lombok.SneakyThrows;
import com.cryptopals.set_6.RSAHelperExt;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.function.UnaryOperator;

/**
 * Created by Andrei Ilchenko on 20-03-19.
 */
public class Set6 {
    public static final String   PLAIN_TEXT = "{\n" +
            "  time: 1356304276,\n" +
            "  social: '555-55-5555',\n" +
            "}";
    private static final Random   RANDOM = new Random(); // Thread safe

    static BigInteger  breakChallenge41(BigInteger cipherTxt, RSAHelper.PublicKey pk,
                                        UnaryOperator<BigInteger> oracle) {
        BigInteger   s;
        while (BigInteger.ONE.compareTo(s = new BigInteger(pk.getModulus().bitLength(), RANDOM).mod(pk.getModulus())) >= 0);
        return  oracle.apply(s.modPow(pk.getE(), pk.getModulus()).multiply(cipherTxt).mod(pk.getModulus()))
                .multiply(s.modInverse(pk.getModulus())).mod(pk.getModulus());
    }

    @SneakyThrows
    static BigInteger  forgeSignature(byte msg[], RSAHelper.PublicKey pk, RSAHelperExt.HashMethod method) {
        final int   MIN_PAD = 4;   // \x00\x01\xff\x00"
        MessageDigest md = MessageDigest.getInstance(method.toString());
        byte[]   hash = md.digest(msg),  paddedMsg;
        int      lenPad = pk.getModulus().bitLength() / 8 - (hash.length + method.getASN1Encoding().length + MIN_PAD + 1);
        paddedMsg = new byte[lenPad + hash.length + method.getASN1Encoding().length + MIN_PAD];
        paddedMsg[1] = 1;     paddedMsg[2] = -1;
        System.arraycopy(method.getASN1Encoding(), 0, paddedMsg, MIN_PAD , method.getASN1Encoding().length);
        System.arraycopy(hash, 0, paddedMsg, MIN_PAD + method.getASN1Encoding().length, hash.length);
        Arrays.fill(paddedMsg, paddedMsg.length - 3, paddedMsg.length, (byte) -1);
        BigInteger  forgedSignature = Set5.ithroot(new BigInteger(paddedMsg), 3);
        return  forgedSignature.add(BigInteger.ONE);
    }

    public static void main(String[] args) {

        try {
            System.out.println("Challenge 41");
            RSAHelperExt   rsa = new RSAHelperExt(BigInteger.valueOf(17));
            BigInteger     cipherTxt = rsa.encrypt(new BigInteger(PLAIN_TEXT.getBytes()));
            System.out.println("Decrypted ciphertext:\n" + new String(rsa.decrypt(cipherTxt).toByteArray()));
            assert rsa.decrypt(cipherTxt).equals(BigInteger.ZERO);
            System.out.println("Obtained ciphertext:\n" + new String(
                    breakChallenge41(cipherTxt, rsa.getPublicKey(), rsa::decrypt).toByteArray()));

            System.out.println("\nChallenge 42");
            byte   msg[] = "hi mom".getBytes();
            rsa = new RSAHelperExt(BigInteger.valueOf(3));
            BigInteger   signature = rsa.sign(msg, RSAHelperExt.HashMethod.SHA1);
            System.out.println("Valid signature verifies? " + rsa.verify(msg, signature));
            System.out.println("Forged signature verifies? "
                    + rsa.verify(msg, forgeSignature(msg, rsa.getPublicKey(), RSAHelperExt.HashMethod.SHA1)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
