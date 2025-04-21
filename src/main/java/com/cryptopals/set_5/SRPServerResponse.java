package com.cryptopals.set_5;

import java.io.Serializable;
import java.math.BigInteger;

public record  SRPServerResponse(long salt, BigInteger B) implements Serializable { }
