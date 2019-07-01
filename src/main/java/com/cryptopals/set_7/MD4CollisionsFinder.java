package com.cryptopals.set_7;

import lombok.ToString;
import sun.security.provider.MD4;

import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static sun.security.provider.MD4Ext.squashBytesToIntsLittle;
import static sun.security.provider.MD4Ext.spreadIntsToBytesLittle;

/**
 * Implements the attack for finding collisions for MD4 as explained in
 * <a href="https://link.springer.com/content/pdf/10.1007%2F11426639_1.pdf">the paper by X. Wang et al.</a>
 * <br>
 * Created by Andrei Ilchenko on 22-06-19.
 */
public class MD4CollisionsFinder {
    // rotation constants
    private static final int   S11 = 3,  S12 = 7,  S13 = 11,  S14 = 19,  S21 = 3,  S22 = 5,  S23 = 9, S24 = 13,
                               S31 = 3,  S32 = 9,  S33 = 11,  S34 = 15,
                               perms[][] = { { 0, 1, 2, 3 }, { 3, 0, 1, 2 }, { 2, 3, 0, 1 }, { 1, 2, 3, 0 } };

    private static int FF(int a, int b, int c, int d, int x, int s) {
        a += (b & c | ~b & d) + x;
        return a << s | a >>> 32 - s;
    }

    private static int GG(int a, int b, int c, int d, int x, int s) {
        a += (b & c | b & d | c & d) + x + 0x5a827999;
        return a << s | a >>> 32 - s;
    }

    private static int  makeBitsEqual(int chainVarTrg, int chainVar2, int i) {
        return  chainVarTrg ^ (chainVarTrg ^ chainVar2) & 1 << i;
    }

    private static int unFF(int updatedChainVar, int a, int b, int c, int d, int s) {
        return  (updatedChainVar >>> s | updatedChainVar << 32 - s) - a - (b & c | ~b & d);
    }

    private static int unGG(int updatedChainVar, int a, int b, int c, int d, int s) {
        return  (updatedChainVar >>> s | updatedChainVar << 32 - s) - a - (b & c | b & d | c & d) - 0x5a827999;
    }

    /**
     * Represents one of the 48 Steps of MD4.
     */
    abstract class Step {
        final int   idx,  s;
        final List<Constraint>   constraints = new ArrayList<>();
        Step(int index, int shift) {
            idx = index;     s = shift;
        }

        /**
         * Represents a constraint from Page 16 of X. Wang et al. paper. Some steps have multiple constraints.
         */
        @ToString
        abstract class Constraint {
            int   bitIdx;
            Constraint(int index) {
                bitIdx = index;
            }
            abstract int  enforceConstraint(int chainVar);
            abstract boolean  checkConstraint();

        }
        @ToString(callSuper = true)
        class  BitsEqualConstraint extends Constraint {
            int   shift;
            BitsEqualConstraint(int index) {
                super(index);
            }
            BitsEqualConstraint(int index, int shft) {
                super(index);     shift = shft;
            }
            @Override
            int  enforceConstraint(int chainVar) {
                int   perm[] = perms[idx % 4];
                return  makeBitsEqual(chainVar, state[perm[1 + shift]], bitIdx);
            }
            @Override
            boolean  checkConstraint() {
                int   perm[] = perms[idx % 4];
                return  ((state[perm[0]] ^ state[perm[1 + shift]]) & 1 << bitIdx) == 0;
            }
        }
        @ToString(callSuper = true)
        class  BitEqualsZeroConstraint extends Constraint {
            BitEqualsZeroConstraint(int index) {
                super(index);
            }
            @Override
            int enforceConstraint(int chainVar) {
                return  chainVar & ~(1 << bitIdx);
            }
            @Override
            boolean checkConstraint() {
                int   perm[] = perms[idx % 4];
                return (state[perm[0]] & 1 << bitIdx) == 0;
            }
        }
        @ToString(callSuper = true)
        class  BitEqualsOneConstraint extends Constraint {
            BitEqualsOneConstraint(int index) {
                super(index);
            }
            @Override
            int  enforceConstraint(int chainVar) {
                return  chainVar | 1 << bitIdx;
            }
            @Override
            boolean checkConstraint() {
                int   perm[] = perms[idx % 4];
                return (state[perm[0]] & 1 << bitIdx) != 0;
            }
        }

        abstract int  doStep();

        int  applyConstraints(int chainVar) {
            for (Constraint constr : constraints) {
                chainVar = constr.enforceConstraint(chainVar);
            }
            return  chainVar;
        }

        boolean  checkConstraints() {
            boolean  res = true;
            for (Constraint constr : constraints) {
                if (!constr.checkConstraint()) {
                    // System.out.printf("Constraint %s failed for step #%d%n", constr.toString(), idx);
                    res = false;
                }
            }
            return  res;
        }

        Step  withBitsEqualConstraint(int bitIndex) {
            return  withBitsEqualConstraint(bitIndex, 0);
        }
        Step  withBitsEqualConstraint(int bitIndex, int shift) {
            constraints.add(new BitsEqualConstraint(bitIndex, shift));
            return  this;
        }
        Step  withBitEqualsZeroConstraint(int bitIndex) {
            constraints.add(new BitEqualsZeroConstraint(bitIndex));
            return  this;
        }
        Step  withBitEqualsOneConstraint(int bitIndex) {
            constraints.add(new BitEqualsOneConstraint(bitIndex));
            return  this;
        }
    }

    public class FStep extends Step {
        FStep(int shift) {
            super(steps.size(), shift);
        }

        @Override
        boolean checkConstraints() {
            int   perm[] = perms[idx % 4];
            state[perm[0]] = FF(state[perm[0]], state[perm[1]], state[perm[2]], state[perm[3]], x[idx], s);
            return  super.checkConstraints();
        }

        @Override
        public int  doStep() {
            int   perm[] = perms[idx % 4],  chainVar = FF(state[perm[0]], state[perm[1]], state[perm[2]], state[perm[3]], x[idx], s);
            chainVar = applyConstraints(chainVar);
            x[idx] = unFF(chainVar, state[perm[0]], state[perm[1]], state[perm[2]], state[perm[3]], s);
            return  state[perm[0]] = chainVar;
        }
    }

    public class GStep extends Step {
        GStep(int shift) {
            super(steps.size(), shift);
        }

        @Override
        boolean checkConstraints() {
            int   perm[] = perms[idx % 4],  xIndex = idx % 16 << 2;
            state[perm[0]] = GG(state[perm[0]], state[perm[1]], state[perm[2]], state[perm[3]], x[xIndex], s);
            return  super.checkConstraints();
        }

        @Override
        int  doStep() {
            int   perm[] = perms[idx % 4],  xIndex = idx % 16 << 2,
                    chainVar = GG(state[perm[0]], state[perm[1]], state[perm[2]], state[perm[3]], x[xIndex], s);
            chainVar = applyConstraints(chainVar);
            x[xIndex] = unGG(chainVar, state[perm[0]], state[perm[1]], state[perm[2]], state[perm[3]], s);
            Step   step = steps.get(xIndex);

            // Updating the chain var from 16 steps before
            firstRoundchainVars[xIndex + 4] = FF(firstRoundchainVars[xIndex], firstRoundchainVars[xIndex+3],
                    firstRoundchainVars[xIndex+2], firstRoundchainVars[xIndex+1], x[xIndex], step.s);

            // a0, d0, c0, b0, a1, d1, c1, b1, a2, d2, c2, b2, ...
            //  0,  1,  2,  3,  4,  5,  6,  7,  8
            for (int i = 1; i < 5; i++) {
                step = steps.get(xIndex + i);
                x[xIndex + i] = unFF(firstRoundchainVars[xIndex + 4 + i], firstRoundchainVars[xIndex + 4 + i - 4],
                        firstRoundchainVars[xIndex + 4 + i - 1], firstRoundchainVars[xIndex + 4 + i - 2], firstRoundchainVars[xIndex + 4 + i - 3], step.s);
            }

            return  state[perm[0]] = chainVar;
        }
    }

    private final static int   A = 0x67452301,  B = 0xefcdab89,  C = 0x98badcfe,  D = 0x10325476;
    private final byte[]   m;
    private final int[]    x,  state = { A, B, C, D },  firstRoundchainVars;
    private final List<Step>   steps = new ArrayList<>();


    private MD4CollisionsFinder() {
        m = new byte[64];
        new Random().nextBytes(m);
        x = new int[16];
        squashBytesToIntsLittle(m, 0, x, 0, 16);

        // Round #1
        Stream.of(S11, S12, S13, S14, S11, S12, S13, S14, S11, S12, S13, S14, S11, S12, S13, S14).forEach(s -> steps.add(new FStep(s)));

        Step   step = steps.get(0);
        step.withBitsEqualConstraint(6);

        step = steps.get(1);
        step.withBitEqualsZeroConstraint(6).withBitsEqualConstraint(7).withBitsEqualConstraint(10);

        step = steps.get(2);
        // c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
        step.withBitEqualsOneConstraint(6).withBitEqualsOneConstraint(7).withBitEqualsZeroConstraint(10).withBitsEqualConstraint(25);

        step = steps.get(3);
        // b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
        step.withBitEqualsOneConstraint(6).withBitEqualsZeroConstraint(7).withBitEqualsZeroConstraint(10).withBitEqualsZeroConstraint(25);

        step = steps.get(4);
        // a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
        step.withBitEqualsOneConstraint(7).withBitEqualsOneConstraint(10).withBitEqualsZeroConstraint(25).withBitsEqualConstraint(13);

        step = steps.get(5);
        // d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
        step.withBitsEqualConstraint(13).withBitsEqualConstraint(18).withBitsEqualConstraint(19)
                .withBitsEqualConstraint(20).withBitsEqualConstraint(21).withBitEqualsOneConstraint(25);

        step = steps.get(6);
        // c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
        step.withBitsEqualConstraint(12).withBitEqualsZeroConstraint(13).withBitsEqualConstraint(14).withBitEqualsZeroConstraint(18)
                .withBitEqualsZeroConstraint(19).withBitEqualsOneConstraint(20).withBitEqualsZeroConstraint(21);

        step = steps.get(7);
        // b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0
        step.withBitEqualsOneConstraint(12).withBitEqualsOneConstraint(13).withBitEqualsZeroConstraint(14)
                .withBitsEqualConstraint(16).withBitEqualsZeroConstraint(18).withBitEqualsZeroConstraint(19)
                .withBitEqualsZeroConstraint(20).withBitEqualsZeroConstraint(21);

        step = steps.get(8);
        // a3,13 =1, a3,14 =1, a3,15 =1, a3,17 =0, a3,19 =0, a3,20 =0, a3,21 =0, a3,22 =1, a3,23 =b2,23, a3,26 =b2,26
        step.withBitEqualsOneConstraint(12).withBitEqualsOneConstraint(13).withBitEqualsOneConstraint(14)
                .withBitEqualsZeroConstraint(16).withBitEqualsZeroConstraint(18).withBitEqualsZeroConstraint(19)
                .withBitEqualsZeroConstraint(20).withBitEqualsOneConstraint(21).withBitsEqualConstraint(22)
                .withBitsEqualConstraint(25);

        step = steps.get(9);
        // d3,13 =1, d3,14 =1, d3,15 =1, d3,17 =0, d3,20 =0, d3,21 =1, d3,22 =1, d3,23 =0, d3,26 = 1, d3,30 = a3,30
        step.withBitEqualsOneConstraint(12).withBitEqualsOneConstraint(13).withBitEqualsOneConstraint(14)
                .withBitEqualsZeroConstraint(16).withBitEqualsZeroConstraint(19).withBitEqualsOneConstraint(20)
                .withBitEqualsOneConstraint(21).withBitEqualsZeroConstraint(22).withBitEqualsOneConstraint(25)
                .withBitsEqualConstraint(29);

        step = steps.get(10);
        // c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
        step.withBitEqualsOneConstraint(16).withBitEqualsZeroConstraint(19).withBitEqualsZeroConstraint(20)
                .withBitEqualsZeroConstraint(21).withBitEqualsZeroConstraint(22).withBitEqualsZeroConstraint(25)
                .withBitEqualsOneConstraint(29).withBitsEqualConstraint(31);

        step = steps.get(11);
        // b3,20 =0, b3,21 =1, b3,22 =1, b3,23 =c3,23, b3,26 =1, b3,30 =0, b3,32 =0
        step.withBitEqualsZeroConstraint(19).withBitEqualsOneConstraint(20).withBitEqualsOneConstraint(21)
                .withBitsEqualConstraint(22).withBitEqualsOneConstraint(25).withBitEqualsZeroConstraint(29)
                .withBitEqualsZeroConstraint(31);

        step = steps.get(12);
        // a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
        step.withBitEqualsZeroConstraint(22).withBitEqualsZeroConstraint(25).withBitsEqualConstraint(26)
                .withBitsEqualConstraint(28).withBitEqualsOneConstraint(29).withBitEqualsZeroConstraint(31);

        step = steps.get(13);
        // d4,23 =0, d4,26 =0, d4,27 =1, d4,29 =1, d4,30 =0, d4,32 =1
        step.withBitEqualsZeroConstraint(22).withBitEqualsZeroConstraint(25).withBitEqualsOneConstraint(26)
                .withBitEqualsOneConstraint(28).withBitEqualsZeroConstraint(29).withBitEqualsOneConstraint(31);

        step = steps.get(14);
        // c4,19 =d4,19, c4,23 =1, c4,26 =1, c4,27 =0, c4,29 =0, c4,30 =0
        step.withBitsEqualConstraint(18).withBitEqualsOneConstraint(22).withBitEqualsOneConstraint(25)
                .withBitEqualsZeroConstraint(26).withBitEqualsZeroConstraint(28).withBitEqualsZeroConstraint(29);

        step = steps.get(15);
        // b4,19 =0, b4,26 =1, b4,27 =1, b4,29 =1, b4,30 =0
        step.withBitEqualsZeroConstraint(18).withBitEqualsOneConstraint(25).withBitEqualsOneConstraint(26)
                .withBitEqualsOneConstraint(28).withBitEqualsZeroConstraint(29);

        firstRoundchainVars = IntStream.concat(IntStream.of(A, D, C, B),
                steps.stream().mapToInt(Step::doStep)).toArray();  /* Does the actual steps of the 1st round of MD4 */

        // Round #2
        Stream.of(S21, S22/*, S23, S24, S21, S22, S23, S24, S21, S22, S23, S24, S21, S22, S23, S24*/).forEach(s -> steps.add(new GStep(s)));
        step = steps.get(16);
        // a5,19 = c4,19, a5,26 = 1, a5,27 = 0, a5,29 = 1, a5,32 = 1
        step.withBitsEqualConstraint(18, 1).withBitEqualsOneConstraint(25).withBitEqualsZeroConstraint(26)
                .withBitEqualsOneConstraint(28).withBitEqualsOneConstraint(31);

        step = steps.get(17);
        // d5,19 = a5,19, d5,26 = b4,26, d5,27 = b4,27, d5,29 = b4,29, d5,32 = b4,32
        step.withBitsEqualConstraint(18).withBitsEqualConstraint(25, 1)
                .withBitsEqualConstraint(26, 1).withBitsEqualConstraint(28, 1)
                .withBitsEqualConstraint(31, 1);

        steps.subList(16, steps.size()).forEach(Step::doStep);
        spreadIntsToBytesLittle(x, 0, m, 0, 16);
    }


    /**
     * Checks if all constraints pass. Enforcing the first 3 constraints for Step 17 sometimes mess up some of
     * the constraints from Step 4 or 5.
     */
    private boolean  checkForWeakness() {
        state[0] = A;     state[1] = B;     state[2] = C;     state[3] = D;
        return  steps.stream().allMatch(Step::checkConstraints);
    }

    /**
     * Returns m' from whose collision differential with m is expected to be zero with a hight probability
     * if all constraints are satisfied. See Page 7 of of X. Wang et al. paper.
     */
    private byte[]  getMPrime() {
        int[]   x_ = x.clone();
        x_[1] = x[1] + (1 << 31);
        x_[2] = x[2] + (1 << 31) - (1 << 28);
        x_[12] = x[12] - (1 << 16);
        byte[]   m_ = new byte[64];
        spreadIntsToBytesLittle(x_, 0, m_, 0, 16);
        return  m_;
    }

    private static class MessagesChecker implements Callable<byte[][]> {
        static AtomicBoolean   ready = new AtomicBoolean();

        @Override
        public byte[][] call() {
            MessageDigest   md4 = MD4.getInstance();
            long   cnt = 0;
            while (true) {
                MD4CollisionsFinder   finder = new MD4CollisionsFinder();
                if (!finder.checkForWeakness())  continue;
                byte[]   m_ = finder.getMPrime(),  digest = md4.digest(finder.m);

                if (Arrays.equals(digest, md4.digest(m_))) {
                    ready.compareAndSet(false, true);
                    return  new byte[][]  {  finder.m,  m_,  digest };
                }
                if (cnt++ % 10_000_000 == 0) {
                    System.out.printf("Worker %s processed %d messages%n", Thread.currentThread().getName(), cnt);
                    if (ready.get()) {
                        return null;
                    }
                }
            }
        }
    }

    /**
     * @return a 3 element array containing byte arrays. The first two elements are the messages that consitute
     * and MD4 collision. The last message is their MD4 hash.
     */
    public static byte[][]  findCollision() throws ExecutionException, InterruptedException {
        int   concurrency = Runtime.getRuntime().availableProcessors();
        ExecutorService   executor = Executors.newFixedThreadPool(concurrency);
        try {
            List<Future<byte[][]>> futures = new ArrayList<>(concurrency);
            for (int i = 0; i < concurrency; i++) {
                futures.add(executor.submit(new MessagesChecker()));
            }
            for (int i = 0; i < concurrency; i++) {
                if (futures.get(i).get() != null) {
                    return futures.get(i).get();
                }
            }
        } finally {
            executor.shutdown();
        }
        return  null;
    }

}
