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
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.cryptopals.Set8.CHALLENGE56_MSG;
import static com.cryptopals.Set8.CURVE_25519_ORDER;
import static com.cryptopals.Set8.CURVE_25519_PRIME;
import static com.cryptopals.set_8.BooleanMatrixOperations.*;
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
    void PolynomialRing() {
        ZpField   field = new ZpField(53);
        PolynomialRing2<ZpField.ZpFieldElement>   poly1 = new PolynomialRing2<>(
                IntStream.of(3, 43, 5, 5, 8, 10).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
            poly2 = new PolynomialRing2<>(IntStream.of(7, 44, 6, 4).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
            product = new PolynomialRing2<>(IntStream.of(21, 9, 37, 48, 1, 48, 31, 39, 40).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
            derivative = new PolynomialRing2<>(IntStream.of(9, 21, 38, 4, 28, 27, 8, 2).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
            xPlus1Cubed = new PolynomialRing2<>(IntStream.of(1, 3, 3, 1).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
            xPlus1Squared = new PolynomialRing2<>(IntStream.of(1, 2, 1).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
            xPlus1xPlus2 = new PolynomialRing2<>(IntStream.of(2, 3, 1).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new));
        System.out.println("p: "+ poly1 + "\nq: " + poly2);
        System.out.println("p+q: " + poly1.add(poly2));

        assertEquals(poly1.add(poly2), poly2.add(poly1));
        assertEquals(poly1, poly2.add(poly1).subtract(poly2));
        assertEquals(poly1, poly1.add(poly2).subtract(poly2));
        assertEquals(poly1.getZeroPolynomial(), poly1.subtract(poly1));
        System.out.println("p*q: " + poly1.multiply(poly2));
        assertEquals(poly1.multiply(poly2), poly2.multiply(poly1));
        assertEquals(product, poly1.multiply(poly2));

        PolynomialRing2<ZpField.ZpFieldElement>   quotient = poly1.divide(poly2),  remainder = poly1.subtract(quotient.multiply(poly2)),
            quotientAndRemainder[] = poly1.divideAndRemainder(poly2);
        System.out.println("p/q: " + quotient);
        System.out.println("p/q * q: " + quotient.multiply(poly2));
        assertEquals(quotient, quotientAndRemainder[0]);
        System.out.println("p%q: " + remainder);
        assertEquals(remainder, quotientAndRemainder[1]);

        // Differentiation
        System.out.println("p': " + poly1.differentiate() + "\nq': " + poly2.differentiate());
        System.out.println("(p*q)': " + poly1.multiply(poly2).differentiate());
        assertEquals(derivative, product.differentiate());

        System.out.println(xPlus1Cubed.gcd(xPlus1Squared));
        assertEquals(xPlus1Cubed.gcd(xPlus1Squared), xPlus1Squared.gcd(xPlus1Cubed));
        System.out.println(xPlus1Cubed.squareFreeFactorization());
        System.out.println(xPlus1Squared.squareFreeFactorization());
        System.out.println(xPlus1xPlus2.equalDegreeFactorization(1));

        BigInteger   power = new BigInteger("545");

        remainder = poly1.scale(power).divideAndRemainder(poly2)[1];
        assertEquals(remainder, poly1.scaleMod(power, poly2));
        System.out.println("Remainder1: " + remainder + "\nRemainder2: " + poly1.scaleMod(power, poly2));


        field = new ZpField(3);
        poly1 = new PolynomialRing2<>(
                IntStream.of(1, 0, 2, 2, 0, 1, 1, 0, 2, 2, 0, 1).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new));
        PolynomialRing2<ZpField.ZpFieldElement>   factor1 = new PolynomialRing2<>(
                        IntStream.of(1, 1).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
                factor2 = new PolynomialRing2<>(
                        IntStream.of(2, 1).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new)),
                factor3 = new PolynomialRing2<>(
                        IntStream.of(1, 0, 1).mapToObj(field::createElement).toArray(ZpField.ZpFieldElement[]::new));
        ;
        List<PolynomialRing2.PolynomialAndPower<ZpField.ZpFieldElement>>  factors = poly1.squareFreeFactorization(),
                expectedFactors = new ArrayList<>();
        expectedFactors.add(new PolynomialRing2.PolynomialAndPower<>(factor1, 1));
        expectedFactors.add(new PolynomialRing2.PolynomialAndPower<>(factor2, 4));
        expectedFactors.add(new PolynomialRing2.PolynomialAndPower<>(factor3, 3));
        assertEquals(expectedFactors, factors);

        System.out.print("\nThe factorization of " + poly1 + " is: ");
        for (PolynomialRing2.PolynomialAndPower<ZpField.ZpFieldElement> factor : factors) {
            System.out.print("(" + factor.getFactor() + ")");
            if (factor.getPower() > 1) System.out.printf("^%d", factor.getPower());
        }

        for (PolynomialRing2.PolynomialAndPower<ZpField.ZpFieldElement> factor : factors) {
            System.out.printf("%nFactor: %s breaks down into: ", factor.getFactor().toString());
            List<PolynomialRing2<ZpField.ZpFieldElement>>  factors__ = factor.getFactor().distinctDegreeFactorization();
            factors__.forEach(x -> System.out.print("(" + x + ")"));
        }

    }

    @DisplayName("https://toadstyle.org/cryptopals/63.txt")
    @Test
    void challenge63() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        SecretKey key = aesKeyGen.generateKey();
        GCM   gcm = new GCM(key);
        final byte[]   nonce = new byte[12],  plnText = CHALLENGE56_MSG.getBytes(),  plnText2 = "dummy text to try".getBytes(),
                 cTxt1,  cTxt2,  assocData = "valid assoc.Data".getBytes();
        new SecureRandom().nextBytes(nonce);
        // a0 || a1 || c0 || c1 || c2 || (len(AD) || len(C)) || t
        cTxt1 = gcm.cipher(plnText, assocData, nonce);
        // Reusing the same nonce, thereby making ourselves vulnerable to the attack.
        cTxt2 = gcm.cipher(plnText2, assocData, nonce);


        PolynomialRing2<PolynomialGaloisFieldOverGF2.FieldElement>   poly1 = GCM.toPolynomialRing2(cTxt1, assocData),
                                                                     poly2 = GCM.toPolynomialRing2(cTxt2, assocData),
                                                                     equation = poly1.add(poly2).toMonicPolynomial();
        System.out.println("cTxt1 polynomial: " + poly1);
        System.out.println("cTxt2 polynomial: " + poly2);
        System.out.println("Equation: " + equation);

        List<PolynomialRing2<PolynomialGaloisFieldOverGF2.FieldElement>>
                allFactors = equation.squareFreeFactorization().stream().map(PolynomialRing2.PolynomialAndPower::getFactor)
                        .flatMap(x -> x.distinctDegreeFactorization().stream()).collect(Collectors.toList()),

                oneDegreeFactors = allFactors.stream().filter(x -> x.intDegree() == 1).collect(Collectors.toList()),

                oneDegreeFactorsThroughEdf = allFactors.stream().filter(x -> x.intDegree() > 1)
                    .flatMap(x -> x.equalDegreeFactorization(1).stream()).collect(Collectors.toList());

        System.out.println("Actual authentication key: " + gcm.getAuthenticationKey());
        System.out.println("Candidates found after square-free and distinct-degree factorization: " + oneDegreeFactors);
        System.out.println("Additional candidates found after equal-degree factorization: " + oneDegreeFactorsThroughEdf);

        oneDegreeFactors.addAll(oneDegreeFactorsThroughEdf);
        List<PolynomialGaloisFieldOverGF2.FieldElement>   candidateAuthenticationKeys =
                oneDegreeFactors.stream().map(x -> x.getCoef(0)).collect(Collectors.toList());
        assertTrue(candidateAuthenticationKeys.contains(gcm.getAuthenticationKey()));

        // Now that we have recovered the authentication key, we can forge a bogus ciphertext that will authenticate.
        byte[]   additionalBogusAssociatedData = "bogus assoc.Data".getBytes(),  forgedCipherTxt,
                 plainTxt;
        for (PolynomialGaloisFieldOverGF2.FieldElement candidateAuthenticationKey : candidateAuthenticationKeys) {
            forgedCipherTxt = GCM.forgeCipherText(cTxt1, assocData, additionalBogusAssociatedData, candidateAuthenticationKey);
            assertNotEquals(forgedCipherTxt, cTxt1);
            plainTxt = gcm.decipher(forgedCipherTxt, additionalBogusAssociatedData, nonce);
            System.out.println("\nRecovered authentication key: " + candidateAuthenticationKey);
            System.out.println("Legit associated data: " + new String(assocData));
            System.out.println("Bogus associated data: " + new String(additionalBogusAssociatedData));
            System.out.println("Legit  cipher text: " + DatatypeConverter.printHexBinary(cTxt1));
            System.out.println("Forged cipher text: " + DatatypeConverter.printHexBinary(forgedCipherTxt));
            System.out.println("Decrypted by the crypto system under attack into: "
                    + (plainTxt == null ? "\u22A5" : new String(plainTxt)) );
        }

    }

    @DisplayName("Linear algebra over GF(2)")
    @Test
    void  linearAlgebraForChallenge64()  {
        BigInteger   modulus = ONE.shiftLeft(128).or(valueOf(135));
        PolynomialGaloisFieldOverGF2   gf = new PolynomialGaloisFieldOverGF2(modulus);
        PolynomialGaloisFieldOverGF2.FieldElement   c = gf.createElement(valueOf(3)),  y = gf.createElement(valueOf(15));

        assertEquals(c.multiply(y), gf.createElement(multiply(c.asMatrix(), y.asVector())) );
        assertEquals(y.multiply(y), gf.createElement(multiply(gf.getSquaringMatrix(), y.asVector())) );

        assertEquals(c, gf.createElement(multiply(c.asMatrix(), gf.getMultiplicativeIdentity().asVector())) );

        assertEquals(y, gf.createElement(y.asVector()));

        boolean[][][]   mss = new boolean[18][][];
        mss[0] = gf.getSquaringMatrix();
        for (int i=1; i < 18; i++) {
            mss[i] = multiply(mss[i-1], mss[0]);
        }
        assertEquals(y.scale(valueOf(2)), gf.createElement(multiply(mss[0],  y.asVector()) ));
        assertEquals(y.scale(valueOf(4)), gf.createElement(multiply(mss[1],  y.asVector()) ));
        assertEquals(y.scale(valueOf(8)), gf.createElement(multiply(mss[2],  y.asVector()) ));
        assertEquals(y.scale(valueOf(16)), gf.createElement(multiply(mss[3],  y.asVector()) ));
        assertEquals(y.scale(valueOf(32)), gf.createElement(multiply(mss[4],  y.asVector()) ));
        assertEquals(y.scale(valueOf(64)), gf.createElement(multiply(mss[5],  y.asVector()) ));
        assertEquals(y.scale(valueOf(128)), gf.createElement(multiply(mss[6],  y.asVector()) ));
        assertEquals(y.scale(valueOf(256)), gf.createElement(multiply(mss[7],  y.asVector()) ));

        // Mc * Ms^i * y) = c * y^4
        assertEquals(c.multiply(y.scale(valueOf(16))),
                gf.createElement(multiply(multiply(c.asMatrix(), mss[3]), y.asVector())) );

        // Confirm matrix representation of GHASH works correctly
        PolynomialGaloisFieldOverGF2.FieldElement    c1 = gf.createRandomElement(),  c2 = gf.createRandomElement(),
                c4 = gf.createRandomElement(),  c8 = gf.createRandomElement(),  h = gf.createRandomElement(),  tag1,  tag2;
        // t = c1*h + c2*h^2 + c4*h^4 + c8*h^8

        // First calculate the tag using plain GF(2^128)
        tag1 = c1.multiply(h).add(c2.multiply(h.scale(valueOf(2)))).add(c4.multiply(h.scale(valueOf(4)))).add(c8.multiply(h.scale(valueOf(8))));
        // Then do the same using a matrix-based representation of GF(2^128) operations
        tag2 = gf.createElement(multiply(add(add(add(c1.asMatrix(), multiply(c2.asMatrix(), mss[0])), multiply(c4.asMatrix(), mss[1])), multiply(c8.asMatrix(), mss[2])), h.asVector()));
        assertEquals(tag1, tag2);


        // Basic GF(2) matrix operations tests on a 5x6 boolean matrix
        boolean[][]   m = { { true, true, false, false, true, true },
                            { true, true, false, true, false, false },
                            { false, true, true, true, false, false  },
                            { false, false, true, false, false, false },
                            { false, false, false, true, true, false } },  mt = transpose(m),  t,  t2;

        // Confirm that transposition works correctly
        assertTrue(BooleanMatrixOperations.equals(m, transpose(mt)));

        t = appendIdentityMatrix(mt);
        // Confirm that appending identity matrices to the right and to the bottom works correctly
        assertTrue(BooleanMatrixOperations.equals(t, transpose(appendIdentityMatrixBottom(m))));

        gaussianElimination(t, m.length);

        t2 = appendIdentityMatrixBottom(m);
        gaussianEliminationColumnEchelonForm(t2);

        // Confirm that row echelon form and column echelon form Gaussian elimination works correctly
        boolean   basis[][] = extractBasisMatrix(t),  basis2[][] = extractBasisMatrixBottom(t2),
                  expectedBasis[] = { false, true, false, true, true, false },
                  expectedProduct[] = new boolean[m.length];
        assertEquals(1, basis.length);
        assertEquals(1, basis2.length);
        assertArrayEquals(expectedBasis, basis[0]);
        assertArrayEquals(expectedBasis, basis2[0]);
        for (boolean[] bs : basis) {
            assertArrayEquals(expectedProduct, multiply(m, bs));
        }

        // Confirm that basis extraction works correctly for random-filled 2048x2176 GF(2) matrices
        m = new boolean[16 << 7][17 << 7];
        Random rnd = new Random();
        expectedProduct = new boolean[m.length];

        // 10 tries should be enough to ascertain correctness
        int   numValid = 0;
        for (int cnt=0; cnt < 10; cnt++) {

            for (int i = 0; i < m.length; i++) {
                for (int j = 0; j < m[0].length; j++) {
                    m[i][j] = rnd.nextBoolean();
                }
            }

            mt = transpose(m);
            t = appendIdentityMatrix(mt);
            gaussianElimination(t, m.length);
            basis = extractBasisMatrix(t);
            System.out.println("Basis size: " + basis.length);
            int   len = 0;

            for (boolean[] bs : basis) {
                // m x bs should be a null column vector
                if (Arrays.equals(expectedProduct, multiply(m, bs))) {
                    len++;
                }
            }
            // Confirm that m x bs == 0 for every element of the basis
            System.out.println("Actual size: " + len);
            // assertEquals(basis.length, len);
            if (len > 0)  numValid++;

        }

        // Not every random-filled matrix will have a basis, however the probability that all ten tries lead to no
        // basis is negligible.
        assertTrue(numValid > 0);
    }

    @DisplayName("https://toadstyle.org/cryptopals/64.txt")
    @Test
    void  challenge64() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        SecretKey key = aesKeyGen.generateKey();

        // Going for 2^8 bytes of plain text => 2^4 blocks
        byte[]   nonce = new byte[12],  plainText = Set8.getPlainText("plain", 21),  pTxt2,  cTxt1,  cTxt2;
        new SecureRandom().nextBytes(nonce);

        // Confirm that we get the same ciphertext as that obtained from a reference implementation.
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Create GCMParameterSpec
        // Going for a 32-bit tag is forbidden by the JRE
        // java.security.InvalidAlgorithmParameterException: Unsupported TLen value; must be one of {128, 120, 112, 104, 96}

        GCMParameterSpec   gcmParameterSpec = new GCMParameterSpec(16 * 8 /*12 * 8*/, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        cTxt1 = cipher.doFinal(plainText);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        assertArrayEquals(plainText, cipher.doFinal(cTxt1));

        // Confirm that the extraction and replacement of the coefficients of x^i works for i being a power of 2.
        PolynomialGaloisFieldOverGF2.FieldElement[]  coeffs = GCM.extractPowerOf2Blocks(cTxt1, plainText.length),
                coeffsPrime = coeffs.clone();
        cTxt2 = GCM.replacePowerOf2Blocks(cTxt1, plainText.length, coeffs);
        assertArrayEquals(cTxt1, cTxt2);

        coeffsPrime[0] = coeffsPrime[0].getMultiplicativeIdentity();
        cTxt2 = GCM.replacePowerOf2Blocks(cTxt1, plainText.length, coeffsPrime);
        assertFalse(Arrays.equals(cTxt1, cTxt2));

        GCM   gcm = new GCM(key);
        GCMExistentialForgeryHelper   h = new GCMExistentialForgeryHelper(cTxt1, plainText.length);

        boolean[][]   T = h.getDependencyMatrix(),  Tt = transpose(T),  ad,  adPrime = new boolean[128][128];
        assertTrue(BooleanMatrixOperations.equals(T, transpose(Tt)));

        coeffs = h.getPowerOf2Blocks();
        coeffsPrime = h.getRandomPowerOf2Blocks();

        // Confirm that ad is calculated correctly
        ad = h.calculateAd(coeffsPrime);
        PolynomialGaloisFieldOverGF2.FieldElement   hash1 = gcm.ghashPower2BlocksDifferences(h.getPowerOf2Blocks(), coeffsPrime),
                    hash2 = coeffs[0].group().createElement(multiply(ad, gcm.getAuthenticationKey().asVector()));
        assertEquals(hash1, hash2);

        // Validate whether the dependency matrix is calculated correctly by calculating the first (n-1)*128 rows of ad
        // indirectly using the dependency matrix, the result is in adPrime. Then compare the first (n-1)*128 rows
        // of adPrime with the corresponding rows of ad
        for (int i=0; i < coeffs.length; i++) {
            PolynomialGaloisFieldOverGF2.FieldElement   di = coeffs[i].subtract(coeffsPrime[i]);
            for (int b=0; b < 128; b++) {
                if (di.getCoefficient(b)) {
                    for (int j=0; j < T.length; j++) {
                        if (T[j][i * 128 + b]) {
                            adPrime[j / 128][j % 128] ^= true;
                        }
                    }
                }
            }
        }

        // The first (n-1)*128 rows of ad and adPrime must be the same
        for (int i=0; i < T.length; i++) {
            assertTrue(ad[i / 128][i % 128] == adPrime[i / 128][i % 128]);
        }

        // 128 x 256 -> 256 x 128 -> 256 x 384
        boolean[][]   tmp = appendIdentityMatrix(Tt),  basis;

        // If the basis was calculated correctly, for each element d of the basis, the product T * d = 0.
        boolean[]     expectedProduct = new boolean[T.length],  product;
        List<boolean[]>   verifiedBasis = new ArrayList<>();
        gaussianElimination(tmp, T.length);
        basis = extractBasisMatrix(tmp);
        System.out.println("\nBasis:");
        for (int i=0; i < basis.length; i++) {
            product = multiply(T, basis[i]);
            if (Arrays.equals(product, expectedProduct)) {
                verifiedBasis.add(basis[i]);
            }
            System.out.println(Arrays.toString(product));
        }

        System.out.printf("Basis size == %d, Verified basis size == %d%n", basis.length, verifiedBasis.size());


        byte[]   assocData = {};
        // Attempt at an existential forgery
        while (true) {
            coeffsPrime = h.forgePowerOf2Blocks();
            if (!gcm.ghashPower2BlocksDifferences(coeffs, coeffsPrime).equals(coeffs[0].getAdditiveIdentity()))  continue;

            cTxt2 = GCM.replacePowerOf2Blocks(cTxt1, plainText.length, coeffsPrime);
            System.out.println(new String(gcm.decipher(cTxt1, assocData, nonce)));
            pTxt2 = gcm.decipher(cTxt2, assocData, nonce);
            System.out.println(pTxt2 == null  ?  "" : new String(gcm.decipher(cTxt2, assocData, nonce)));


            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            try {
                pTxt2 = cipher.doFinal(cTxt2);
                break;
            } catch (AEADBadTagException e) {
                // ignore
            }
        }

        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        final byte[]   cTxt = cTxt2;
        assertDoesNotThrow(() -> cipher.doFinal(cTxt));
        System.out.println("Success with an existential forgery against GCM:\n" + new String(pTxt2));

    }
}
