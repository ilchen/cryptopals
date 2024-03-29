/*
 * Copyright (c) 1996, 2012, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun.security.modifiedprovider;

import java.nio.ByteBuffer;

/**
 * This class implements the Secure Hash Algorithm (SHA) developed by
 * the National Institute of Standards and Technology along with the
 * National Security Agency.  This is the updated version of SHA
 * fip-180 as superseded by fip-180-1.
 *
 * <p>It implement JavaSecurity MessageDigest, and can be used by in
 * the Java Security framework, as a pluggable implementation, as a
 * filter for the digest stream classes.
 *
 * @author      Roger Riggs
 * @author      Benjamin Renaud
 * @author      Andreas Sterbenz
 */
public final class SHA1 extends DigestBase1 {

    // Buffer of int's and count of characters accumulated
    // 64 bytes are included in each hash block so the low order
    // bits of count are used to know how to pack the bytes into ints
    // and to know when to compute the block and start the next one.
    private int[] W;

    // state of this
    private int[] state;

    /**
     * Creates a new SHA object.
     */
    public SHA1() {
        super("SHA-1", 20, 64);
        state = new int[5];
        W = new int[80];
        implReset();
    }

    /*
     * Clones this object.
     */
    public Object clone() throws CloneNotSupportedException {
        SHA1 copy = (SHA1) super.clone();
        copy.state = copy.state.clone();
        copy.W = new int[80];
        return copy;
    }

    /**
     * Resets the buffers and hash value to start a new hash.
     */
    void implReset() {
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
        state[4] = 0xc3d2e1f0;
    }

    /**
     * Computes the final hash and copies the 20 bytes to the output array.
     */
    void implDigest(byte[] out, int ofs) {
        long bitsProcessed = bytesProcessed << 3;

        int index = (int)bytesProcessed & 0x3f;
        int padLen = (index < 56) ? (56 - index) : (120 - index);
        engineUpdate(padding, 0, padLen);

        ByteBuffer  bb = ByteBuffer.allocate(8);
        bb.putLong(bitsProcessed);
        System.arraycopy(bb.array(), 0, buffer, 56, 8);
        implCompress(buffer, 0);

        spreadIntsToBytes(state, 0, out, ofs, 5);
    }

    // Constants for each round
    private final static int round1_kt = 0x5a827999;
    private final static int round2_kt = 0x6ed9eba1;
    private final static int round3_kt = 0x8f1bbcdc;
    private final static int round4_kt = 0xca62c1d6;


    /**
     * Hack for https://cryptopals.com/sets/4/challenges/29
     */
    @Override
    protected void embedNewState(int[] state, long bProcessed) {
        bytesProcessed = bProcessed;
        this.state[0] = state[0];
        this.state[1] = state[1];
        this.state[2] = state[2];
        this.state[3] = state[3];
        this.state[4] = state[4];
    }


    public static void squashBytesToInts(byte[] inBytes, int inOff, int[] outInts, int outOff, int intLen) {
        for (int i = 0; i < intLen; ++i)
            outInts[outOff + i] =
                    ((inBytes[inOff + i * 4] & 0xff) << 24) |
                            ((inBytes[inOff + i * 4 + 1] & 0xff) << 16) |
                            ((inBytes[inOff + i * 4 + 2] & 0xff) << 8) |
                            (inBytes[inOff + i * 4 + 3] & 0xff);
    }

    /// Spread ints into bytes.
    static void spreadIntsToBytes(int[] inInts, int inOff, byte[] outBytes, int outOff, int intLen) {
        for (int i = 0; i < intLen; ++i) {
            outBytes[outOff + i * 4] = (byte) (inInts[inOff + i] >>> 24);
            outBytes[outOff + i * 4 + 1] = (byte) (inInts[inOff + i] >>> 16);
            outBytes[outOff + i * 4 + 2] = (byte) (inInts[inOff + i] >>> 8);
            outBytes[outOff + i * 4 + 3] = (byte) inInts[inOff + i];
        }
    }
    /**
     * Compute a the hash for the current block.
     *
     * This is in the same vein as Peter Gutmann's algorithm listed in
     * the back of Applied Cryptography, Compact implementation of
     * "old" NIST Secure Hash Algorithm.
     */
    void implCompress(byte[] buf, int ofs) {
        // b2iBig64(buf, ofs, W);
        squashBytesToInts(buf, ofs, W, 0,16);

        // The first 16 ints have the byte stream, compute the rest of
        // the buffer
        for (int t = 16; t <= 79; t++) {
            int temp = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
            W[t] = (temp << 1) | (temp >>> 31);
        }

        int a = state[0];
        int b = state[1];
        int c = state[2];
        int d = state[3];
        int e = state[4];

        // Round 1
        for (int i = 0; i < 20; i++) {
            int temp = ((a<<5) | (a>>>(32-5))) +
                    ((b&c)|((~b)&d))+ e + W[i] + round1_kt;
            e = d;
            d = c;
            c = ((b<<30) | (b>>>(32-30)));
            b = a;
            a = temp;
        }

        // Round 2
        for (int i = 20; i < 40; i++) {
            int temp = ((a<<5) | (a>>>(32-5))) +
                    (b ^ c ^ d) + e + W[i] + round2_kt;
            e = d;
            d = c;
            c = ((b<<30) | (b>>>(32-30)));
            b = a;
            a = temp;
        }

        // Round 3
        for (int i = 40; i < 60; i++) {
            int temp = ((a<<5) | (a>>>(32-5))) +
                    ((b&c)|(b&d)|(c&d)) + e + W[i] + round3_kt;
            e = d;
            d = c;
            c = ((b<<30) | (b>>>(32-30)));
            b = a;
            a = temp;
        }

        // Round 4
        for (int i = 60; i < 80; i++) {
            int temp = ((a<<5) | (a>>>(32-5))) +
                    (b ^ c ^ d) + e + W[i] + round4_kt;
            e = d;
            d = c;
            c = ((b<<30) | (b>>>(32-30)));
            b = a;
            a = temp;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

}