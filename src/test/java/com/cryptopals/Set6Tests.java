package com.cryptopals;

import com.cryptopals.set_6.DSAHelper;
import com.cryptopals.set_6.PaddingOracleHelper;
import com.cryptopals.set_6.RSAHelperExt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.stream.Stream;

import static com.cryptopals.Set6.*;
import static com.cryptopals.set_6.DSAHelper.newBigInteger;
import static org.junit.jupiter.api.Assertions.*;

class Set6Tests {
    @DisplayName("https://cryptopals.com/sets/6/challenges/41")
    @Test
    void  challenge41()  {
        RSAHelperExt rsa = new RSAHelperExt(BigInteger.valueOf(17));
        BigInteger   cipherTxt = rsa.encrypt(new BigInteger(PLAIN_TEXT.getBytes()));
        rsa.decrypt(cipherTxt);   // Only one decryption allowed
        assertEquals(BigInteger.ZERO, rsa.decrypt(cipherTxt));
        assertArrayEquals(PLAIN_TEXT.getBytes(),
                          Set6.breakChallenge41(cipherTxt, rsa.getPublicKey(), rsa::decrypt).toByteArray());
    }

    @DisplayName("https://cryptopals.com/sets/6/challenges/42")
    @Test
    void  challenge42()  {
        byte   msg[] = "hi mom".getBytes();
        RSAHelperExt   rsa = new RSAHelperExt(BigInteger.valueOf(3));
        BigInteger   signature = rsa.sign(msg, RSAHelperExt.HashMethod.SHA1);
        assertTrue(rsa.verify(msg, signature), "Valid signature didn't verify");
        assertTrue(rsa.verify(msg, forgeSignature(msg, rsa.getPublicKey(), RSAHelperExt.HashMethod.SHA1)),
                "Forged signature didn't verify");
    }

    @DisplayName("https://cryptopals.com/sets/6/challenges/43")
    @Test
    void  challenge43()  {
        assertAll("DSA basics",
                () -> {
                    DSAHelper   dsa = new DSAHelper();
                    DSAHelper.PublicKey   pk = dsa.getPublicKey();
                    DSAHelper.Signature   dsaSignature = dsa.sign(CHALLENGE_43_TEXT.getBytes());
                    assertTrue(pk.verifySignature(CHALLENGE_43_TEXT.getBytes(), dsaSignature),
                            "Signature doesn't verify");
                },
                () -> {
                    DSAHelper   dsa = new DSAHelper(DSAHelper.P, DSAHelper.Q, DSAHelper.G);
                    DSAHelper.PublicKey   pk = dsa.getPublicKey();
                    DSAHelper.Signature   dsaSignature = dsa.sign(CHALLENGE_43_TEXT.getBytes());
                    assertTrue(pk.verifySignature(CHALLENGE_43_TEXT.getBytes(), dsaSignature),
                            "Signature doesn't verify, standard P, Q, and G were used");
                },
                () -> {
                    MessageDigest sha = MessageDigest.getInstance("SHA-1");
                    BigInteger   h = newBigInteger(sha.digest(CHALLENGE_43_TEXT.getBytes()));
                    assertEquals("d2d0714f014a9784047eaeccf956520045c45265", h.toString(16),
                            "Wrong conversion of hash to a BigInteger");
                },
                () -> {
                    MessageDigest   sha = MessageDigest.getInstance("SHA-1");
                    DSAHelper.PublicKey pk = new DSAHelper.PublicKey(DSAHelper.P, DSAHelper.Q, DSAHelper.G, CHALLENGE_43_Y);
                    BigInteger   x = breakChallenge43(CHALLENGE_43_TEXT.getBytes(), CHALLANGE_43_SIGNATURE, pk);
                    assertEquals(new BigInteger("125489817134406768603130881762531825565433175625"), x,
                            "Wrong key found");
                    assertEquals("954edd5e0afe5542a4adf012611a91912a3ec16",
                            newBigInteger(sha.digest(x.toString(16).getBytes())).toString(16));
                });

    }

    @DisplayName("https://cryptopals.com/sets/6/challenges/44")
    @ParameterizedTest
    @ArgumentsSource(Challenge44ArgumentsProvider.class)
    void  challenge44(String url) throws NoSuchAlgorithmException {
        MessageDigest   sha = MessageDigest.getInstance("SHA-1");
        List<SignedMessage> signatures = extractSignatures(url);
        DSAHelper.PublicKey   pk = new DSAHelper.PublicKey(DSAHelper.P, DSAHelper.Q, DSAHelper.G, CHALLENGE_44_Y);
        BigInteger   x = breakChallenge44(signatures, pk);
        assertEquals("ca8f6f7c66fa362d40760d135b763eb8527d3d52",
                newBigInteger(sha.digest(x.toString(16).getBytes())).toString(16));
    }

    static class Challenge44ArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(Arguments.of(getClass().getClassLoader().getResource("challenge44.txt").toString()));
        }
    }

    @DisplayName("https://cryptopals.com/sets/6/challenges/46")
    @Test
    void  challenge46() {
        RSAHelperExt   rsa = new RSAHelperExt(BigInteger.valueOf(17));
        BigInteger     cipherTxt = rsa.encrypt(newBigInteger(CHALLANGE_46_PLAINTEXT));
        BigInteger  plainText = breakChallenge46(cipherTxt, rsa.getPublicKey(), rsa::decryptionOracle);
        assertArrayEquals(CHALLANGE_46_PLAINTEXT, plainText.toByteArray(),
                "Didn't succeed in obtaining correct plaintext");
    }

    /**
     * @param numBits  number of bits in each prime factor of an RSA modulus, i.e. the modulus is thus {@code 2*numBits} long
     */
    @DisplayName("https://cryptopals.com/sets/6/challenges/47 and https://cryptopals.com/sets/6/challenges/48")
    @ParameterizedTest @ValueSource(ints = { 128, 384, 512, 768, 1024 })
    void  challenges47and48(int numBits) {
        RSAHelperExt rsa = new RSAHelperExt(BigInteger.valueOf(17), numBits);
        BigInteger   plainText = RSAHelperExt.pkcs15Pad(CHALLANGE_47_PLAINTEXT.getBytes(),
                                                        rsa.getPublicKey().modulus().bitLength());
        BigInteger   cipherTxt = rsa.encrypt(plainText);
        BigInteger   crackedPlainText = PaddingOracleHelper.solve(cipherTxt, rsa.getPublicKey(), rsa::paddingOracle);
        assertArrayEquals(CHALLANGE_47_PLAINTEXT.getBytes(), rsa.pkcs15Unpad(crackedPlainText));
    }

}
