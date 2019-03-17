package com.cryptopals.set_5;

import lombok.Data;

import java.math.BigInteger;

@Data
public class SRPClientSession {
    final SRPClientState   state;
    final byte   K[];
    boolean   valid;
}
