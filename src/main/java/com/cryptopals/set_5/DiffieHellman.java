package com.cryptopals.set_5;

import java.math.BigInteger;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;

public interface DiffieHellman extends Remote {
    BigInteger  initiate(BigInteger p, BigInteger g, BigInteger A) throws RemoteException;
    byte[]  echo(byte msg[]) throws RemoteException;
}
