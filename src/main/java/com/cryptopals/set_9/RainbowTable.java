package com.cryptopals.set_9;

import sun.security.provider.MD4;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.stream.IntStream;

/**
 * Constructs a rainbow table for passwords made up out of ascii-32-95 characters hashed with MD4 or any other
 * one-way hash function.
 */
public class RainbowTable {
    public static final int   CHAR_SET_SIZE = 95;
    private final long   l;
    private final int   tau,  numChars;
    private final ConcurrentMap<ByteBuffer, byte[]>   rainbowTable;   /* z -> pw */
    private final String   hashAlgoName;

    /**
     * Constructs a rainbow table for passwords made up out of {@code numChars} ascii-32-95 characters hashed with
     * {@code hashAlgorithmName} one-way hash function.
     */
    public RainbowTable(int numChars, String hashAlgorithmName) {
        l = (long) Math.ceil(Math.pow(CHAR_SET_SIZE, (numChars << 1) / 3.));
        tau = (int) Math.ceil(Math.pow(CHAR_SET_SIZE, numChars / 3.));
        this.numChars = numChars;
        rainbowTable = new ConcurrentHashMap<>();
        hashAlgoName = hashAlgorithmName;

        System.out.printf("N: %d, l: %d, \u03C4: %d, l*\u03C4: %d, hash algorithm: %s%n",
                (long) Math.pow(CHAR_SET_SIZE, numChars), l, tau, l*tau, hashAlgorithmName);

        // Task that will be run in parallel to populate rows [range[0], range[1]) of the rainbow table
        Consumer<long[]> task = (range) -> {
            System.out.printf("%s is populating rows %s of the rainbow table%n", Thread.currentThread(), Arrays.toString(range));
            try {
                MessageDigest   md = hashAlgorithmName.equals("MD4")  ?  MD4.getInstance()
                                                                      :  MessageDigest.getInstance(hashAlgorithmName);
                Random         rnd = new SecureRandom();
                byte[]   pw,  z,  collision;
                for (long i=range[0]; i < range[1]; i++) {
                    do {
                        z = pw = getPlainText(numChars, rnd);
                        for (int j=0; j < tau; j++) {
                            z = fi(j, md, z);
                        }
                        collision = rainbowTable.putIfAbsent(ByteBuffer.wrap(z), pw);
                    }  while (collision != null); // Takes on average 3 tries to obtain a non-merging chain

                }
            } catch (Exception e) {
                // ignore
            }
        };

        // To speed things up, constructing rows in the rainbow table in parallel using all cores.
        int   concurrency = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        long   step = l / concurrency;

        CompletableFuture<?>[] res = IntStream.range(0, concurrency).mapToObj(
                x -> CompletableFuture.completedFuture(
                        new long[] { x * step, x + 1 == concurrency ?  l : (x + 1) * step }))
                .map(x -> x.thenAcceptAsync(task, executor)).toArray(CompletableFuture<?>[]::new);
        CompletableFuture.allOf(res).join();
    }

    public byte[]  crackPassword(byte[] hash) throws NoSuchAlgorithmException {
        byte[]   z = gi(tau-1, hash);
        MessageDigest   md = hashAlgoName.equals("MD4")  ?  MD4.getInstance()
                                                         :  MessageDigest.getInstance(hashAlgoName);
        byte[]   pw;
        for (int i=tau-2; i >= 0; i--) {
            if (null != (pw = rainbowTable.get(ByteBuffer.wrap(z)))) {
                //System.out.printf("Match for z: %s -> corresponding pw: %s%n", new String(z), new String(pw));
                for (int j=0; j <= i; j++) {
                    pw = fi(j, md, pw);
                }
                if (Arrays.equals(md.digest(pw), hash))  return  pw;
            }
            z = gi(i, hash);
            for (int j=i+1; j < tau; j++) {
                z = fi(j, md, z);
            }
        }

        return  null;
    }


    public byte[]  fi(int i, MessageDigest md, byte[] pw) {
        return  gi(i, md.digest(pw));
    }

    private byte[]  gi(int i, byte[] hash) {
        return  toAscii3295((ByteBuffer.wrap(hash).getLong() & 0x7fffffffffffffffL) + i, numChars);
    }

    /**
     * Converts an arbitrary string of bits represented by {@code m} into {@code numChars} ascii-32-95 symbols.
     */
    private static byte[]  toAscii3295(long m, int numChars) {
        if (m < 0)  m &= 0x7fffffffffffffffL;
        byte[]   res = new byte[numChars];
        for (int i=res.length-1; i >= 0; i--) {
            res[i] = (byte) (m % CHAR_SET_SIZE + 32);
            m /= CHAR_SET_SIZE;
        }
        return  res;
    }

    /**
     * Generates a piece of plain text composed of random ASCII-32-95 characters so that the resultant
     * piece of text is {@code numChars} characters long.
     */
    public static byte[]  getPlainText(int numChars, Random rnd) {
        StringBuilder   res = new StringBuilder();
        int  i = 0;
        while (i++ < numChars) {
            res.append((char) (32 + rnd.nextInt(95)));
        }
        return  res.toString().getBytes();
    }

    public static boolean  isAscii3295(byte[] m) {
        return IntStream.range(0, m.length).map(i -> (int) m[i]).noneMatch(x -> x < 32);
    }

}
