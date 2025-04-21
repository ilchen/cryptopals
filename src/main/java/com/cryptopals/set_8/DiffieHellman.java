package com.cryptopals.set_8;

import com.cryptopals.Set8;

import java.math.BigInteger;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface DiffieHellman extends Remote {
    /**
     * @param p  a prime defining a group Zp*
     * @param g  a generator of a (sub)group of Zp*
     * @param q  the order of the generator
     * @param A  Alice's public key
     */
    Set8.Challenge57DHBobResponse  initiate(BigInteger p, BigInteger g, BigInteger q, BigInteger A) throws RemoteException;

    /**
     * Can be called only once before a new private key will get generated
     */
    boolean  isValidPrivateKey(BigInteger b) throws RemoteException;
}
