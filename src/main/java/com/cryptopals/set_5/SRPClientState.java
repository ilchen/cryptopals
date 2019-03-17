package com.cryptopals.set_5;

import lombok.Data;

import java.math.BigInteger;

@Data
public class SRPClientState {
    final SRPHelper    srpHelper;
    final long         salt;
    final BigInteger   verifier;
}
