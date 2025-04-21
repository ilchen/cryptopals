package com.cryptopals.set_5;

import com.cryptopals.Set1;
import com.cryptopals.Set4;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.cryptopals.set_5.DiffieHellmanHelper.decryptMessage;

public class SRPService extends UnicastRemoteObject implements SRP {
    private final Map<String, SRPClientState>   clientState = new ConcurrentHashMap<>();
    private final Map<String, SRPClientSession> sessions = new ConcurrentHashMap<>();

    public SRPService() throws RemoteException {
        super();
    }

    @Override
    public void register(BigInteger p, BigInteger g, BigInteger k, byte[] I, byte[] P) throws RemoteException {
        SRPHelper srpHelper = new SRPHelper(p, g, k);
        long    salt = srpHelper.getFreshSalt();
        clientState.put(new String(I), new SRPClientState(srpHelper, salt, srpHelper.generateVerifier(salt, P)));
    }

    @Override
    public SRPServerResponse initiate(byte[] I, BigInteger A) throws RemoteException {
        String   email = new String(I);
        SRPClientState   state = clientState.get(email);
        SRPHelper    helper = state.srpHelper();
        BigInteger   b = helper.generateExp(),  B = helper.generatePublicServerKey(state.verifier(), b);
        SRPClientSession   s = new SRPClientSession(state, helper.generateKeyServer(A, B, b, state.verifier()));
        sessions.put(email, s);
        return  new SRPServerResponse(state.salt(), B);
    }

    @Override
    public boolean  handshake(byte[] I, byte[] hmac) throws RemoteException {
        String   email = new String(I);
        SRPClientSession   s = sessions.get(email);
        try {
            // Unlimited strength JCE required
            Set4   encryptor = new Set4(Cipher.ENCRYPT_MODE, new SecretKeySpec(s.getK(), "AES"));
            byte   expectedHmac[]= encryptor.hmac(SRPHelper.longAsBytes(s.getState().salt()),
                                                  MessageDigest.getInstance("SHA-256"));
            if (Arrays.equals(hmac, expectedHmac)) {
                s.setValid(true);
            }
            System.out.printf("HMAC: %s%nExpected HMAC: %s%n",
                    Set1.printHexBinary(hmac), Set1.printHexBinary(expectedHmac));
        } catch (Exception e) {
            throw  new RemoteException(e.getMessage(), e);
        }
        return  s.isValid();
    }

    @Override
    public byte[] echo(byte[] I, byte[] cipherText) throws RemoteException {
        String   email = new String(I);
        SRPClientSession   s = sessions.get(email);
        if (!s.isValid()) {
            throw  new RemoteException("Illegal state for user: " + email);
        }
        byte   msg[] = decryptMessage(cipherText, s.getK());
        System.out.printf("%nReceived message '%s'%n", new String(msg));
        SRPHelper  helper = s.getState().srpHelper();
        return  helper.encryptMessage(msg, s.getK());
    }
}
