package com.cryptopals;

import com.cryptopals.set_5.RSAHelper;
import com.cryptopals.set_6.DSAHelper;
import com.cryptopals.set_6.PaddingOracleHelper;
import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import com.cryptopals.set_6.RSAHelperExt;

import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.stream.IntStream;

import static com.cryptopals.set_6.DSAHelper.fromHash;
import static com.cryptopals.set_6.DSAHelper.TWO;

/**
 * Created by Andrei Ilchenko on 20-03-19.
 */
public class Set6 {
    static final String   PLAIN_TEXT = "{\n" +
            "  time: 1356304276,\n" +
            "  social: '555-55-5555',\n" +
            "}",
            CHALLENGE_43_TEXT = "For those that envy a MC it can be hazardous to your health\n"
                    + "So be friendly, a matter of life and death, just like a etch-a-sketch\n",
            CHALLANGE_47_PLAINTEXT = "kick it, CC";
    static final BigInteger   CHALLENGE_43_Y = new BigInteger("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4" +
            "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004" +
            "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed" +
            "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b" +
            "bb283e6633451e535c45513b2d33c99ea17", 16),
        CHALLENGE_44_Y = new BigInteger("2d026f4bf30195ede3a088da85e398ef869611d0f68f07" +
            "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8" +
            "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519" +
            "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430" +
            "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3" +
            "2971c3de5084cce04a2e147821", 16);
    static final DSAHelper.Signature   CHALLANGE_43_SIGNATURE = new DSAHelper.Signature(
            new BigInteger("548099063082341131477253921760299949438196259240", 10),
            new BigInteger("857042759984254168557880549501802188789837994940", 10));
    static final byte   CHALLANGE_46_PLAINTEXT[] = DatatypeConverter.parseBase64Binary(
            "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==");
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

    @Data @Builder
    static class  SignedMessage  {
        final String   msg;
        final BigInteger   m;
        final DSAHelper.Signature   signature;
    }

    @SneakyThrows
    static List<SignedMessage>  extractSignatures(String url) throws IOException {
        final String   MSG = "msg: ",  S = "s: ",  R = "r: ",  M = "m: ";
        final int   maxLines = 600;
        try (InputStream is = new URL(url).openStream(); BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            MessageDigest   sha = MessageDigest.getInstance("SHA-1");
            String   line;
            List<SignedMessage>   res = new ArrayList<>();
            SignedMessage.SignedMessageBuilder   smb = null;
            DSAHelper.Signature.SignatureBuilder   sb = null;
            for (int i=0; i < maxLines  &&  (line = reader.readLine()) != null; i++)  {
                if (line.startsWith(MSG)) {
                    String   msg = line.substring(MSG.length());
                    smb = SignedMessage.builder().msg(msg).m(fromHash(sha.digest(msg.getBytes())));
                } else if (line.startsWith(S)) {
                    sb = DSAHelper.Signature.builder().s(new BigInteger(line.substring(S.length())) );
                } else if (line.startsWith(R)) {
                    sb.r(new BigInteger(line.substring(R.length())) );
                    smb.signature(sb.build());
                } else if (line.startsWith(M)) {
                    SignedMessage  sm = smb.build();
                    BigInteger   m = new BigInteger(line.substring(M.length()), 16);
                    if (!m.equals(sm.getM())) {
                        throw  new IllegalStateException(String.format("The hash of msg %s 0x%x != 0x%x",
                                sm.getMsg(), m, sm.getM()));
                    }
                    res.add(sm);
                }
            }
            return  res;
        }
    }

    static BigInteger  breakChallenge44(List<SignedMessage> signatures, DSAHelper.PublicKey pk) {
        for (int i=0; i < signatures.size(); i++) {
            for (int j=i+1; j < signatures.size(); j++) {
                BigInteger   m1 = signatures.get(i).getM(),  m2 = signatures.get(j).getM(),
                             s1 = signatures.get(i).getSignature().getS(),  s2 = signatures.get(j).getSignature().getS(),
                             r1 = signatures.get(i).getSignature().getR();
                BigInteger   k = m1.subtract(m2).multiply(s1.subtract(s2).modInverse(pk.getQ())),
                             x = s1.multiply(k).subtract(m1).multiply(r1.modInverse(pk.getQ())).mod(pk.getQ());
                if (pk.getG().modPow(x, pk.getP()).equals(pk.getY())) {
                    return  x;
                }
            }
        }
        return  BigInteger.ZERO;
    }

    static BigInteger  breakChallenge46(BigInteger cipherTxt, RSAHelper.PublicKey pk,
                                        Predicate<BigInteger> oracle) {
        System.out.printf("Ciphertext: %x%n", cipherTxt);
        BigInteger   modulus = pk.getModulus(),  lower = BigInteger.ZERO,  upper = BigInteger.ONE,  denom = BigInteger.ONE,
                     multiplier = TWO.modPow(pk.getE(), modulus),  cur = cipherTxt,  d;
        int   n = modulus.bitLength();
        for (int i=0; i < n; i++) {
            cur = cur.multiply(multiplier);
//            tmp = upper.add(lower).divide(TWO);   // Here upper starts at the modulus. This approach turns out
//                                                     to be numerically unstable and fails to decrypt the least
//                                                     significant byte of the ciphertext. Replaced with an approach
//                                                     below.
            d = upper.subtract(lower);
            upper = upper.multiply(TWO);
            lower = lower.multiply(TWO);
            denom = denom.multiply(TWO);
            if (oracle.test(cur)) { // It didn't wrap the modulus
                upper = upper.subtract(d);
//                upper = tmp; // Not stable, abandoned
            } else {                // It wrapped the modulus
                lower = lower.add(d);
//                lower = tmp; // Not stable, abandoned
            }

            System.out.printf("%4d %s%n", i,        // Hollywood style :-)
                    new String(upper.multiply(modulus).divide(denom).toByteArray()).split("[\\n\\r]")[0]);
        }

        return  upper.multiply(modulus).divide(denom);
    }


    public static void main(String[] args) {

        try {
            System.out.println("Challenge 41");
            RSAHelperExt   rsa = new RSAHelperExt(BigInteger.valueOf(17));
            BigInteger     cipherTxt = rsa.encrypt(new BigInteger(PLAIN_TEXT.getBytes()));
            System.out.println("Decrypted ciphertext:\n" + new String(rsa.decrypt(cipherTxt).toByteArray()));
            assert rsa.decrypt(cipherTxt).equals(BigInteger.ZERO);
            System.out.println("Obtained plaintext:\n" + new String(
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
            pk = new DSAHelper.PublicKey(DSAHelper.P, DSAHelper.Q, DSAHelper.G, CHALLENGE_43_Y);
            BigInteger   x = breakChallenge43(CHALLENGE_43_TEXT.getBytes(), CHALLANGE_43_SIGNATURE, pk);
            System.out.printf("Recovered x = %d%nSHA-1 of the hex representation of the private key is: 0x%s%n",
                    x, fromHash(sha.digest(x.toString(16).getBytes())).toString(16));

            System.out.println("\nChallenge 44");
            msg = "Listen for me, you better listen for me now. ".getBytes();
            System.out.printf("m = 0x%x%n", fromHash(sha.digest(msg)));
            List<SignedMessage> signatures = extractSignatures("https://cryptopals.com/static/challenge-data/44.txt");
            pk = new DSAHelper.PublicKey(DSAHelper.P, DSAHelper.Q, DSAHelper.G, CHALLENGE_44_Y);
            x = breakChallenge44(signatures, pk);
            System.out.printf("Recovered x = %d%nSHA-1 of the hex representation of the private key is: 0x%s%n",
                    x, fromHash(sha.digest(x.toString(16).getBytes())).toString(16));

            System.out.println("\nChallenge 45");
            BigInteger   gs[] = new BigInteger[] { BigInteger.ZERO, DSAHelper.P.add(BigInteger.ONE) };
            for (BigInteger  g : gs) {
                dsa = new DSAHelper(DSAHelper.P, DSAHelper.Q, g);
                for (String str : new String[] {"Hello, world", "Goodbye, world"}) {
                    dsaSignature = DSAHelper.Signature.builder().r(g.mod(DSAHelper.P))
                            .s(fromHash(sha.digest(str.getBytes()))).build(); // s could be any value
                    System.out.printf("Forged signature %s for message '%s' with g==%d verifies? %b%n",
                            dsaSignature.toString(), str, g, dsa.getPublicKey().verifySignature(msg, dsaSignature));
                }
            }

            System.out.println("\nChallenge 46");
            cipherTxt = rsa.encrypt(fromHash(CHALLANGE_46_PLAINTEXT));
            BigInteger  plainText = breakChallenge46(cipherTxt, rsa.getPublicKey(), rsa::decryptionOracle);
            msg = plainText.toByteArray();
            System.out.println("Obtained plaintext:\n" + new String(msg));
            assert  Arrays.equals(msg, CHALLANGE_46_PLAINTEXT);

            System.out.println("\nChallenge 47");
            rsa = new RSAHelperExt(BigInteger.valueOf(17), 384);
            plainText = RSAHelperExt.pkcs15Pad(CHALLANGE_47_PLAINTEXT.getBytes(), rsa.getPublicKey().getModulus().bitLength());
            cipherTxt = rsa.encrypt(plainText);
            BigInteger   crackedPlainText = PaddingOracleHelper.solve(cipherTxt, rsa.getPublicKey(), rsa::paddingOracle);
            System.out.printf("%nPlaintext: %x%nCiphertext: %x%nRecovered plaintext: %x%n", plainText, cipherTxt, crackedPlainText);
            System.out.printf("Recovered plaintext: %s%n", new String(rsa.pkcs15Unpad(crackedPlainText)));
            assert  Arrays.equals(rsa.pkcs15Unpad(crackedPlainText), CHALLANGE_47_PLAINTEXT.getBytes());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
