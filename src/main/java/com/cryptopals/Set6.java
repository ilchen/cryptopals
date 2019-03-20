package com.cryptopals;

import com.cryptopals.set_5.RSAHelper;
import set_6.RSAHelperExt;

import java.math.BigInteger;
import java.security.SecureRandom;
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

    public static void main(String[] args) {

        try {
            System.out.println("Challenge 41");
            RSAHelperExt   rsa = new RSAHelperExt(BigInteger.valueOf(17));
            BigInteger     cipherTxt = rsa.encrypt(new BigInteger(PLAIN_TEXT.getBytes()));
            System.out.println("Decrypted ciphertext:\n" + new String(rsa.decrypt(cipherTxt).toByteArray()));
            System.out.println("Decrypted ciphertext:\n" + new String(rsa.decrypt(cipherTxt).toByteArray()));
            System.out.println("Obtained ciphertext:\n" + new String(
                    breakChallenge41(cipherTxt, rsa.getPublicKey(), rsa::decrypt).toByteArray()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
