package com.cryptopals;

import java.util.Random;

public class MT19937 extends Random {
    static final int   W = 32,  N = 624,  M = 397,  R = 31,  F = 1812433253,  U = 11,
                       S = 7,  B = 0x9D2C5680,  T = 15,  C = 0xEFC60000,  L = 18,  A = 0x9908B0DF,
                       LOWER_MASK = (1 << R) - 1,  UPPER_MASK =  ~LOWER_MASK;

    private final int[]   mt = new int[N];
    private int  mti;
    MT19937() {
        this(5489);
    }

    MT19937(long seed) {
        mti = N;
        mt[0] = (int) seed;
        for (int i=1; i < N; i++) { // loop over each element
            mt[i] = F * (mt[i-1] ^ (mt[i-1] >>> W-2)) + i;
        }
    }

    MT19937(int index, int state[]) {
        mti = index;
        System.arraycopy(state, 0, mt, 0, N);
    }

    @Override
    protected int next(int bits) {
        synchronized (mt) {
            if (mti >= N) {
                if (mti > N) {
                    throw new IllegalStateException("Generator was never seeded");
                    // Alternatively, seed with constant value; 5489 is used in reference C code[46]
                }
                twist();
            }

            int y = mt[mti];
            y ^= y >>> U;
            y ^= y << S  &  B;
            y ^= y << T  &  C;
            y ^= y >>> L;

            mti++;
            return  y >>> W - bits;
        }
    }

    private void  twist() {
        for (int i=0; i < N; i++) {
            int x = mt[i] & UPPER_MASK + (mt[(i+1) % N] & LOWER_MASK),  xA = x >>> 1;
            if (x % 2 != 0) { // lowest bit of x is 1
                xA ^= A;
            }
            mt[i] = mt[(i + M) % N] ^ xA;
        }
        mti = 0;
    }
}
