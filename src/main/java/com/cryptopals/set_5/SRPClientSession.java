package com.cryptopals.set_5;

import lombok.Data;

@Data
public class SRPClientSession {
    final SRPClientState   state;
    final byte   K[];
    boolean   valid;
}
