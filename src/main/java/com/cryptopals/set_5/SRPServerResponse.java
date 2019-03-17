package com.cryptopals.set_5;

import lombok.Data;

import java.io.Serializable;
import java.math.BigInteger;

@Data
public class SRPServerResponse implements Serializable {
    final long   salt;
    final BigInteger   B;
}
