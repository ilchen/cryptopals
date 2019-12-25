package com.cryptopals;

import com.cryptopals.set_5.DiffieHellmanHelper;
import com.cryptopals.set_5.RSAHelper;
import com.cryptopals.set_6.DSAHelper;
import com.cryptopals.set_6.RSAHelperExt;
import com.cryptopals.set_8.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.cryptopals.Set8.CHALLENGE56_MSG;
import static com.cryptopals.Set8.CURVE_25519_ORDER;
import static com.cryptopals.Set8.CURVE_25519_PRIME;
import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.*;

class Set8Tests {

    @DisplayName("https://toadstyle.org/cryptopals/57.txt")
    @ParameterizedTest @ValueSource(strings = { "rmi://localhost/DiffieHellmanBobService" })
    // The corresponding SpringBoot server application must be running.
    void challenge57(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException{

        // First check the implementation of Garner's algorithm for correctness
        BigInteger   test[][] = {
                {  BigInteger.valueOf(2),  BigInteger.valueOf(5) },
                {  BigInteger.valueOf(1),  BigInteger.valueOf(7) },
                {  BigInteger.valueOf(3),  BigInteger.valueOf(11) },
                {  BigInteger.valueOf(8),  BigInteger.valueOf(13) },
        };
        assertEquals(BigInteger.valueOf(2192), Set8.garnersAlgorithm(Arrays.asList(test)));

        // Now check the whole implementation
        BigInteger b = Set8.breakChallenge57(url);
        DiffieHellman bob = (DiffieHellman) Naming.lookup(url);
        assertTrue(bob.isValidPrivateKey(b));
    }

    @DisplayName("Pollard's kangaroo algorithm")
    @Test
    void challenge58PollardsKangaroo() {
        // First check the implementation of J.M. Pollard's algorithm for correctness
        DiffieHellmanHelper dh = new DiffieHellmanHelper(
                new BigInteger("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623"),
                new BigInteger("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357"));

        BigInteger   y = new BigInteger("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119"),
                b = dh.dlog(y, BigInteger.valueOf(2).pow(20), DiffieHellmanHelper::f);
        assertEquals(dh.getGenerator().modPow(b, dh.getModulus()), y);

        y = new BigInteger("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733");
        b = dh.dlog(y, BigInteger.valueOf(2).pow(40), DiffieHellmanHelper::f);
        assertEquals(dh.getGenerator().modPow(b, dh.getModulus()), y);
    }

    @DisplayName("https://toadstyle.org/cryptopals/58.txt")
    @ParameterizedTest @ValueSource(strings = { "rmi://localhost/DiffieHellmanBobService" })
    // The corresponding SpringBoot server application must be running.
    void challenge58(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException{
        BigInteger   b = Set8.breakChallenge58(url);
        DiffieHellman bob = (DiffieHellman) Naming.lookup(url);
        assertTrue(bob.isValidPrivateKey(b));
    }

    @DisplayName("WeierstrassFormECCurve")
    @Test
    void challenge59WeierstrassFormECCurve() {
        WeierstrassECGroup group = new WeierstrassECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(-95051), valueOf(11279326), new BigInteger("233970423115425145498902418297807005944"));
        WeierstrassECGroup.ECGroupElement   base = group.createPoint(
                valueOf(182), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
        assertTrue(group.containsPoint(base));
        assertEquals(group.O, base.scale(q));
    }

    @DisplayName("https://toadstyle.org/cryptopals/59.txt")
    @ParameterizedTest @ValueSource(strings = { "rmi://localhost/ECDiffieHellmanBobService" })
        // The corresponding SpringBoot server application must be running.
    void challenge59(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException {
        WeierstrassECGroup group = new WeierstrassECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(-95051), valueOf(11279326), new BigInteger("233970423115425145498902418297807005944"));
        WeierstrassECGroup.ECGroupElement   base = group.createPoint(
                valueOf(182), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
        BigInteger   b = Set8.breakChallenge59(base, q, url);
        ECDiffieHellman bob = (ECDiffieHellman) Naming.lookup(url);
        assertTrue(bob.isValidPrivateKey(b));
    }

    @DisplayName("MontgomeryFormECCurve")
    @Test
    void challenge60MontgomeryFormECCurve() {
        MontgomeryECGroup group = new MontgomeryECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(534), ONE, new BigInteger("233970423115425145498902418297807005944"));
        MontgomeryECGroup.ECGroupElement base = group.createPoint(
                valueOf(4), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
        assertTrue(group.containsPoint(base));
        assertEquals(group.O, base.scale(q));
        assertEquals(ZERO, base.ladder(q));
    }

    @DisplayName("Pollard's kangaroo algorithm on elliptic curve groups")
    @Test
    void challenge60PollardsKangaroo() {
        MontgomeryECGroup   mgroup = new MontgomeryECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(534), ONE, new BigInteger("233970423115425145498902418297807005944"));
        MontgomeryECGroup.ECGroupElement   mbase = mgroup.createPoint(
                valueOf(4), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   exponent = valueOf(12130);
        assertEquals(exponent, mbase.dlog(mbase.scale(exponent), valueOf(1110000), ECGroupElement::f));
    }

    @DisplayName("https://toadstyle.org/cryptopals/61.txt")
    @Test
    void challenge61ECDSA() {
        MontgomeryECGroup   curve25519 = new MontgomeryECGroup(CURVE_25519_PRIME,
                valueOf(486662), ONE, CURVE_25519_ORDER.shiftRight(3), CURVE_25519_ORDER);
        MontgomeryECGroup.ECGroupElement   curve25519Base = curve25519.createPoint(
                valueOf(9), curve25519.mapToY(valueOf(9)));
        BigInteger   q = curve25519.getCyclicOrder();
        ECDSA   ecdsa = new ECDSA(curve25519Base, q);
        DSAHelper.Signature   signature = ecdsa.sign(CHALLENGE56_MSG.getBytes());
        ECDSA.PublicKey   legitPk = ecdsa.getPublicKey(),
                forgedPk = Set8.breakChallenge61ECDSA(CHALLENGE56_MSG.getBytes(), signature, ecdsa.getPublicKey());
        assertTrue(legitPk.verifySignature(CHALLENGE56_MSG.getBytes(), signature));
        assertTrue(forgedPk.verifySignature(CHALLENGE56_MSG.getBytes(), signature));
        assertNotEquals(legitPk, forgedPk);
    }

    @DisplayName("https://toadstyle.org/cryptopals/61.txt")
    @Test
    void challenge61RSA() {
        RSAHelperExt rsa = new RSAHelperExt(RSAHelper.PUBLIC_EXPONENT, 160);
        BigInteger rsaSignature = rsa.sign(CHALLENGE56_MSG.getBytes(), RSAHelperExt.HashMethod.SHA1);

        RSAHelper.PublicKey legitRSAPk = rsa.getPublicKey(),
                forgedRSAPk = Set8.breakChallenge61RSA(CHALLENGE56_MSG.getBytes(), rsaSignature,
                                                       legitRSAPk.getModulus().bitLength());

        assertTrue(legitRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
        assertTrue(forgedRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
    }

    @DisplayName("https://toadstyle.org/cryptopals/61.txt")
    @Test
    void challenge61RSAPrecomputedPrimes() {
        RSAHelperExt rsa = new RSAHelperExt(new BigInteger("1244531015222089066686014345871128487293834311511"),
                new BigInteger("1203007175264872213635758749034760908717988390329"), RSAHelper.PUBLIC_EXPONENT);
        BigInteger rsaSignature = rsa.sign(CHALLENGE56_MSG.getBytes(), RSAHelperExt.HashMethod.SHA1);

        DiffieHellmanUtils.PrimeAndFactors pq[] = new DiffieHellmanUtils.PrimeAndFactors[]{
                new DiffieHellmanUtils.PrimeAndFactors(
                        new BigInteger("2252226720431925817465020447075111488063403846689"),
                        Stream.of(2, 7, 277, 647, 2039, 2953, 14633, 139123, 479387, 904847).map(BigInteger::valueOf).collect(Collectors.toList())
                ),
                new DiffieHellmanUtils.PrimeAndFactors(
                        new BigInteger("2713856776699319359494147955700110393372009838087"),
                        Stream.of(2, 13, 17, 23, 26141, 56633, 80429, 241567, 652429, 1049941).map(BigInteger::valueOf).collect(Collectors.toList())
                ),
        };

        RSAHelper.PublicKey legitRSAPk = rsa.getPublicKey(),
                            forgedRSAPk = Set8.breakChallenge61RSA(CHALLENGE56_MSG.getBytes(), rsaSignature, pq,
                                                                   legitRSAPk.getModulus().bitLength());
        assertTrue(legitRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
        assertTrue(forgedRSAPk.verify(CHALLENGE56_MSG.getBytes(), rsaSignature));
    }

    @DisplayName("Polynomial Galois Field over GF(2)")
    @Test
    void polynomialGaloisFieldOverGF2() {
        BigInteger   modulus = ONE.shiftLeft(128).or(valueOf(135));
        PolynomialGaloisFieldOverGF2   gf = new PolynomialGaloisFieldOverGF2(modulus);
        PolynomialGaloisFieldOverGF2.FieldElement   a = gf.createElement(valueOf(3)),  b = gf.createElement(valueOf(15));
        System.out.println("a: " + a);
        System.out.println("b: " + b);
        System.out.println("a + b: " + a.add(b));
        assertEquals(a.add(b), gf.createElement(valueOf(12)));
        System.out.println("a * b: " + a.multiply(b));
        assertEquals(a.multiply(b), gf.createElement(valueOf(17)));
        System.out.println("a * modulus: " + a.multiply(gf.createElement(modulus)));
        assertEquals(a.multiply(gf.createElement(modulus)), gf.getAdditiveIdentity());
        System.out.println("a^-1: " + a.modInverse());
        System.out.println("a * a^-1: " + a.multiply(a.modInverse()));
        assertEquals(a.multiply(a.modInverse()), gf.getMultiplicativeIdentity());

        gf = new PolynomialGaloisFieldOverGF2(valueOf(19));
        a = gf.createElement(valueOf(2));
        for (int i=0; i < 1 << 4; i++) {
            System.out.printf("x^%d = %s%n", i, a.scale(valueOf(i)));
        }
        assertEquals(a.scale(gf.getMultiplicativeGroupOrder()), gf.getMultiplicativeIdentity());
        assertEquals(a.scale(gf.getOrder()), a);
    }

    @DisplayName("GCM mode implemented correctly")
    @Test
    void GCM() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        SecretKey key = aesKeyGen.generateKey();
        GCM   gcm = new GCM(key);
        byte[]   nonce = new byte[12],  plnText = CHALLENGE56_MSG.getBytes(),  cTxt1,  cTxt2,  assocData = new byte[0];
        new SecureRandom().nextBytes(nonce);
        cTxt1 = gcm.cipher(plnText, assocData, nonce);

        // Confirm that we get the same ciphertext as that obtained from a reference implementation.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Create GCMParameterSpec
        GCMParameterSpec   gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        cTxt2 = cipher.doFinal(plnText);
        assertArrayEquals(cTxt2, cTxt1);

        // Confirm that decrypting will produce the original plain text
        assertArrayEquals(plnText, gcm.decipher(cTxt1, assocData, nonce));

        // Confirm that garbling a single byte of cipher text will result in the bottom symbol
        cTxt1[0] ^= 0x03;
        assertArrayEquals(null, gcm.decipher(cTxt1, assocData, nonce));
    }

    @DisplayName("Polynomial rings implemented correctly")
    @Test
    void PolynomialsRing() {
        ZpField   field = new ZpField(53);
        int[]   coeff1 = { 3, 43, 5, 5, 8, 10 },  coeff2 = { 7, 44, 6, 4 };
        PolynomialRing<ZpField.ZpFieldElement>   poly1 = new PolynomialRing<>(
                IntStream.of(3, 43, 5, 5, 8, 10).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
            poly2 = new PolynomialRing<>(IntStream.of(7, 44, 6, 4).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new));
        System.out.println(poly1 + "\n" + poly2);
        System.out.println(poly1.add(poly2));

        assertEquals(poly1.add(poly2), poly2.add(poly1));
        assertEquals(poly1, poly2.add(poly1).subtract(poly2));
        assertEquals(poly1, poly1.add(poly2).subtract(poly2));
        assertEquals(poly1.getZeroPolynomial(), poly1.subtract(poly1));
        System.out.println(poly1.multiply(poly2));
        assertEquals(poly1.multiply(poly2), poly2.multiply(poly1));


        PolynomialRing<ZpField.ZpFieldElement>   quotient = poly1.divide(poly2),  remainder = poly1.subtract(quotient.multiply(poly2)),
            quotientAndRemainder[] = poly1.divideAndRemainder(poly2);
        System.out.println(quotient);
        System.out.println(quotient.multiply(poly2));
        assertEquals(quotient, quotientAndRemainder[0]);
        System.out.println(remainder);
        System.out.println(quotient.multiply(poly2).add(remainder));
        assertEquals(remainder, quotientAndRemainder[1]);
    }

    @DisplayName("https://toadstyle.org/cryptopals/61.txt")
    @Test
    void challenge63() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        SecretKey key = aesKeyGen.generateKey();
        GCM   gcm = new GCM(key);
        byte[]   nonce = new byte[12],  plnText = CHALLENGE56_MSG.getBytes(),  plnText2 = "dummy text to try".getBytes(),
                 cTxt1,  cTxt2,  assocData = new byte[0];
        new SecureRandom().nextBytes(nonce);
        // a0 || a1 || c0 || c1 || c2 || (len(AD) || len(C)) || t
        cTxt1 = gcm.cipher(plnText, assocData, nonce);
        // Reusing the same nonce, thereby making ourselves vulnerable to the attack.
        cTxt2 = gcm.cipher(plnText2, assocData, nonce);


        PolynomialRing<PolynomialGaloisFieldOverGF2.FieldElement>   ring1 = GCM.toPolynomialRing(cTxt1),
                                                                    ring2 = GCM.toPolynomialRing(cTxt2),
                                                                    equation = ring1.add(ring2);
        System.out.println(ring1 + "\n" + ring2 + "\n" + equation);
        equation = equation.toMonicPolynomial();
        System.out.println(equation);
    }
}
