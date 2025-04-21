package com.cryptopals.set_5;


import java.math.BigInteger;

public record  SRPClientState(SRPHelper srpHelper, long salt, BigInteger verifier) {  }
