package com.cryptopals;

import com.cryptopals.set_5.RSAHelper;
import com.cryptopals.set_6.DSAHelper;
import lombok.SneakyThrows;
import com.cryptopals.set_6.RSAHelperExt;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.function.UnaryOperator;
import java.util.stream.IntStream;

import static com.cryptopals.set_6.DSAHelper.fromHash;

/**
 * Created by Andrei Ilchenko on 20-03-19.
 */
public class Set6 {
    public static final String   PLAIN_TEXT = "{\n" +
            "  time: 1356304276,\n" +
            "  social: '555-55-5555',\n" +
            "}",
            CHALLENGE_43_TEXT = "For those that envy a MC it can be hazardous to your health\n"
                    + "So be friendly, a matter of life and death, just like a etch-a-sketch\n";
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


    @SneakyThrows
    static BigInteger  breakChallenge43(byte msg[], DSAHelper.Signature signature, DSAHelper.PublicKey pk) {
        MessageDigest   sha = MessageDigest.getInstance("SHA-1");
        BigInteger   h = fromHash(sha.digest(msg));
        return IntStream.rangeClosed(0, 0xffff).parallel().mapToObj(BigInteger::valueOf)
                .map(k -> signature.getS().multiply(k).subtract(h).multiply(signature.getR().modInverse(pk.getQ())).mod(pk.getQ()))
                .filter(x -> pk.getG().modPow(x, pk.getP()).equals(pk.getY())).findFirst().orElseThrow(IllegalStateException::new);
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

            DSAHelper   dsa = new DSAHelper();
            DSAHelper.PublicKey   pk = dsa.getPublicKey();
            DSAHelper.Signature   dsaSignature = dsa.sign(CHALLENGE_43_TEXT.getBytes());
            System.out.println("Signature verifies? " + pk.verifySignature(CHALLENGE_43_TEXT.getBytes(), dsaSignature));

            System.out.println("\nChallenge 43");
            MessageDigest   sha = MessageDigest.getInstance("SHA-1");
            pk = new DSAHelper.PublicKey(DSAHelper.P, DSAHelper.Q, DSAHelper.G,
                    new BigInteger("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4" +
                        "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004" +
                        "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed" +
                        "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b" +
                        "bb283e6633451e535c45513b2d33c99ea17", 16));
            BigInteger   x = breakChallenge43(CHALLENGE_43_TEXT.getBytes(), new DSAHelper.Signature(
                    new BigInteger("548099063082341131477253921760299949438196259240", 10),
                    new BigInteger("857042759984254168557880549501802188789837994940", 10)), pk);
            System.out.printf("Recovered x = %d%nSHA-1 of the hex representation of the private key is: 0x%s%n",
                    x, fromHash(sha.digest(x.toString(16).getBytes())).toString(16));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
