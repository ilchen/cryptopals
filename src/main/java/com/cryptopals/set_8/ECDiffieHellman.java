package com.cryptopals.set_8;

import com.cryptopals.Set8;

import java.math.BigInteger;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ECDiffieHellman extends Remote {
    /**
     * @param g  a generator of a (sub)group of the elliptic curve group that g is a membber of
     * @param q  the order of the generator
     * @param A  Alice's public key
     * @throws RemoteException
     */
    Set8.Challenge59ECDHBobResponse  initiate(ECGroupElement g, BigInteger q, ECGroupElement A) throws RemoteException;

    /**
     * Can be called only once before a new private key will get generated
     */
    boolean  isValidPrivateKey(BigInteger b) throws RemoteException;
}
