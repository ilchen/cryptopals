package com.cryptopals.set_5;

import java.math.BigInteger;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface SRP extends Remote {
    void register(BigInteger p, BigInteger g, BigInteger k, byte I[], byte P[]) throws RemoteException;
    SRPServerResponse  initiate(byte I[], BigInteger A) throws RemoteException;
    boolean  handshake(byte I[], byte hmac[]) throws RemoteException;
    byte[]  echo(byte I[], byte msg[]) throws RemoteException;
}
