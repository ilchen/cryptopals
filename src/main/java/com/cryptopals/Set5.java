package com.cryptopals;

import com.cryptopals.set_5.*;

import static com.cryptopals.set_5.DiffieHellmanHelper.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.rmi.Naming;
import java.security.MessageDigest;
import java.util.Arrays;

public class Set5 {
    public static void main(String[] args) {

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
            if (server.handshake(email, encryptor.hmac(SRPHelper.longAsBytes(resp.getSalt()),
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
                if (server.handshake(email, encryptor.hmac(SRPHelper.longAsBytes(resp.getSalt()),
                        MessageDigest.getInstance("SHA-256")))) {
                    cipherText = server.echo(email, srp.encryptMessage(msg.getBytes(), key));
                    System.out.printf("With A == %d%n-> '%s'%n<- '%s'%n", craftedA,
                            msg, new String(decryptMessage(cipherText, key)));
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
