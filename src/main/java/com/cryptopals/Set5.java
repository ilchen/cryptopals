package com.cryptopals;

import com.cryptopals.set_5.*;

import static com.cryptopals.set_5.DiffieHellmanHelper.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.rmi.Naming;
import java.security.MessageDigest;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Set5 {
    static final int   TIMES = RSAHelper.PUBLIC_EXPONENT.intValue();

    public static BigInteger  ithroot(BigInteger n, int k) {
        final int  k1 = k - 1;
        BigInteger  kBig = BigInteger.valueOf(k),  k1Big = BigInteger.valueOf(k1),  s = n.add(BigInteger.ONE),  u = n;

        while (u.compareTo(s) < 0) {
            s = u;
            u = u.multiply(k1Big).add(n.divide(u.pow(k1))).divide(kBig);
        }
        return s;
    }

    public static boolean  isOdd(BigInteger i) {
        byte[]  repr = i.toByteArray();
        return  (repr[repr.length - 1] & 0x01) != 0;
    }

    private static BigInteger  recoverPlainText(List<BigInteger[]> pairs) {
        if (pairs.size() != TIMES)
            throw  new IllegalArgumentException(TIMES + " { modulus, cipherText} pairs required");
        BigInteger   n012 = BigInteger.ONE,  res = BigInteger.ZERO;
        for (int i=0; i < TIMES; i++) {
            n012 = n012.multiply(pairs.get(i)[0]);
            BigInteger   msi = BigInteger.ONE;
            for (int j = 0; j < TIMES; j++) {
                if (j == i)  continue;
                msi = msi.multiply(pairs.get(j)[0]);
            }
            res = res.add(pairs.get(i)[1].multiply(msi).multiply(msi.modInverse(pairs.get(i)[0])));
        }
        return  ithroot(res.mod(n012), TIMES);
    }

    public static void  main(String[] args) {

        try {
            System.out.println("Challenge 34");
            String   serviceUrls[] = {   "rmi://localhost/DiffieHellmanService",
                                         "rmi://localhost/DiffieHellmanMITMService"   };
            String   msg = "Hello, Server!";
            for (String url : serviceUrls) {
                DiffieHellman server = (DiffieHellman) Naming.lookup(url);
                DiffieHellmanHelper dh = new DiffieHellmanHelper(P, G);
                BigInteger a = dh.generateExp(), A = G.modPow(a, P), B = server.initiate(P, G, A);
                SecretKey  sk = dh.generateSymmetricKey(B, a);
                byte[] cipherText = server.echo(dh.encryptMessage(msg.getBytes(), sk));
                System.out.printf("-> '%s'%n<- '%s'%n", msg, new String(decryptMessage(cipherText, sk)));
            }

            System.out.println("\nChallenge 36");
            byte[]   email = "john.de.groot@gmail.com".getBytes(),  pass = "querty1234567890~G".getBytes();
            SRP   server = (SRP) Naming.lookup("rmi://localhost/SRPService");
            SRPHelper   srp = new SRPHelper(P, G, SRPHelper.K);
            server.register(srp.getModulus(), srp.getGenerator(), srp.getSRPParameter(), email, pass);
            BigInteger   a = srp.generateExp(),  A = srp.getGenerator().modPow(a, srp.getModulus());
            SRPServerResponse  resp = server.initiate(email, A);
            byte[]   key = srp.generateKeyClient(A, resp, a, pass),  cipherText;
            // Unlimited strength JCE required
            Set4   encryptor = new Set4(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            if (server.handshake(email, encryptor.hmac(SRPHelper.longAsBytes(resp.salt()),
                                                       MessageDigest.getInstance("SHA-256")))) {
                cipherText = server.echo(email, srp.encryptMessage(msg.getBytes(), key));
                System.out.printf("-> '%s'%n<- '%s'%n", msg, new String(decryptMessage(cipherText, key)));
            }

            System.out.println("\nChallenge 37");
            BigInteger  craftedAs[] = {   BigInteger.ZERO,
                    srp.getModulus(),  srp.getModulus().multiply(BigInteger.valueOf(2)),
                    srp.getModulus().pow(2)   };
            for (BigInteger craftedA : craftedAs) {
                a = srp.generateExp();
                resp = server.initiate(email, craftedA);     // We don't know the actual password
                key = srp.generateKeyClient(craftedA, resp, a, "dummy@gmail.com".getBytes());
                encryptor = new Set4(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
                if (server.handshake(email, encryptor.hmac(SRPHelper.longAsBytes(resp.salt()),
                        MessageDigest.getInstance("SHA-256")))) {
                    cipherText = server.echo(email, srp.encryptMessage(msg.getBytes(), key));
                    System.out.printf("With A == %d%n-> '%s'%n<- '%s'%n", craftedA,
                            msg, new String(decryptMessage(cipherText, key)));
                }
            }

            System.out.printf("%nChallenge 40%nEncrypting message \"%s\" %d times with different RSA key pairs%n", msg, TIMES);
            List<BigInteger[]> stream = IntStream.range(0, TIMES).mapToObj(x -> new RSAHelper()).map(helper ->
                new BigInteger[] { helper.getPublicKey().modulus(), helper.encrypt(new BigInteger(msg.getBytes())) })
                    .collect(Collectors.toList());

            BigInteger  res = recoverPlainText(stream);

            System.out.printf("Ciphertext '%d' -> \"%s\"", res, new String(res.toByteArray()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
