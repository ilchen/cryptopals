package com.cryptopals;

import com.cryptopals.set_5.DiffieHellmanHelper;
import com.cryptopals.set_8.DiffieHellman;
import com.cryptopals.set_8.ECDiffieHellman;
import com.cryptopals.set_8.ECGroup;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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
        ECGroup group = new ECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(-95051), valueOf(11279326), new BigInteger("233970423115425145498902418297807005944"));
        ECGroup.ECGroupElement   base = group.createPoint(
                valueOf(182), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
        assertTrue(group.containsPoint(base));
        assertEquals(group.O, base.scale(q));
    }

    @DisplayName("https://toadstyle.org/cryptopals/59.txt")
    @ParameterizedTest @ValueSource(strings = { "rmi://localhost/ECDiffieHellmanBobService" })
        // The corresponding SpringBoot server application must be running.
    void challenge59(String url) throws RemoteException, NotBoundException, MalformedURLException,
            NoSuchAlgorithmException, InvalidKeyException{
        ECGroup   group = new ECGroup(new BigInteger("233970423115425145524320034830162017933"),
                valueOf(-95051), valueOf(11279326), new BigInteger("233970423115425145498902418297807005944"));
        ECGroup.ECGroupElement   base = group.createPoint(
                valueOf(182), new BigInteger("85518893674295321206118380980485522083"));
        BigInteger   q = new BigInteger("29246302889428143187362802287225875743");
        BigInteger   b = Set8.breakChallenge59(base, q, url);
        ECDiffieHellman bob = (ECDiffieHellman) Naming.lookup(url);
        assertTrue(bob.isValidPrivateKey(b));
    }
}
