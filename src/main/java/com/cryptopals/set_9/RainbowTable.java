package com.cryptopals.set_9;

import sun.security.provider.MD4;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.stream.IntStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.xml.bind.DatatypeConverter;

/**
 * Constructs a rainbow table for passwords made up out of ascii-32-95 characters hashed with MD4 or any other
 * one-way hash function.
 */
public class RainbowTable {
    public static final String   HMAC_MD5 = "HmacMD5";
    public static final int   CHAR_SET_SIZE = 95;
    private final long   l;
    private final int   tau,  numChars,  numBits;
    private final Mac[]   prfs;
    private final ConcurrentMap<ByteBuffer, byte[]>   rainbowTable;   /* z -> pw */

    /**
     * Constructs a rainbow table for passwords made up out of {@code numChars} ascii-32-95 characters hashed with
     * {@code hashAlgorithmName} one-way hash function.
     */
    public RainbowTable(int numChars, String hashAlgorithmName) throws NoSuchAlgorithmException, InvalidKeyException {
        l = (long) Math.ceil(Math.pow(CHAR_SET_SIZE, (numChars << 1) / 3.));
        tau = (int) Math.ceil(Math.pow(CHAR_SET_SIZE, numChars / 3.));
        numBits = 64 - Long.numberOfLeadingZeros((long) Math.ceil(Math.pow(CHAR_SET_SIZE, numChars)) - 1);
        this.numChars = numChars;
        System.out.printf("l: %d, \u03C4: %d, hash algorithm: %s%n", l, tau, hashAlgorithmName);
        rainbowTable = new ConcurrentHashMap<>();
        KeyGenerator   prfKeyGen = KeyGenerator.getInstance(HMAC_MD5);
        prfs = new Mac[tau];
        for (int i=0; i < tau; i++) {
            prfs[i] = Mac.getInstance(HMAC_MD5);  /* pw = toAscii3295(HMAC_MD5(y)) will do as a PRF */
            prfs[i].init(prfKeyGen.generateKey());
        }
        System.out.printf("%d Y -> P PRFs constructed%n", tau);

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
                            z = fi(j, md, z); // toAscii3295(prfs[i].doFinal(md.digest(z)), numChars, numBits);
                        }
                        collision = rainbowTable.putIfAbsent(ByteBuffer.wrap(z), pw);
//                        if (collision != null) {
//                            System.out.printf("Collision for %s, preimages (%s, %s)%n",
//                                    new String(z), new String(pw), new String(collision));
//                        }
                    }  while (collision != null);
//                    if (i % 100000 == 0) {
//                        System.out.printf("%s just populated row %d of the rainbow table%n", Thread.currentThread(), i);
//                    }
                }
            } catch (Exception e) {
                // ignore
            }
        };
        int   concurrency = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        long   step = l / concurrency;

//        IntStream.range(0, concurrency).mapToObj(
//                x -> new int[] { x * step, x + 1 == concurrency ?  l : (x + 1) * step }).map(Arrays::toString).forEach(System.out::println);

        CompletableFuture<?>[] res = IntStream.range(0, concurrency).mapToObj(
                x -> CompletableFuture.completedFuture(
                        new long[] { x * step, x + 1 == concurrency ?  l : (x + 1) * step })).map(x -> x.thenAcceptAsync(task, executor)).toArray(CompletableFuture<?>[]::new);
        CompletableFuture.allOf(res).join();
    }

    public byte[]  crackPassword(byte[] hash) {
        byte[]   z = gi(tau-1, hash);
        MessageDigest   md = MD4.getInstance();
        byte[]   pw;
        for (int i=tau-2; i >= 0; i--) {
            //  assert  isAscii3295(z)  &&  z.length == numChars;
            if (null != (pw = rainbowTable.get(ByteBuffer.wrap(z)))) {
                System.out.printf("Match for z: %s -> corresponding pw: %s%n", new String(z), new String(pw));
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
        return  toAscii3295(prfs[i].doFinal(hash), numChars, numBits);
    }

    /**
     * Converts an arbitrary string of bits represented by {@code m} into {@code numChars} ascii-32-95 symbols.
     * @param numBits the minimum number of bits required to store {@code numChars} ascii-32-95 symbols
     */
    public static byte[]  toAscii3295(byte[] m, int numChars, int numBits) {
        assert  numChars <= 8  &&  numChars > 2;
/*        if (m.length != 8)  m = Arrays.copyOf(m, 8);
        int   numBitsRoundedUp = numBits + 7 & -8,  i;
        for (i=0; i < 64 - numBitsRoundedUp >> 3; i++) {
            m[i] = 0;
        }

        int  numBitsToZeroOut = (8 - i >> 3) - numBits;
        if (numBitsToZeroOut > 0) {
            m[i] &= (1 << 8 - numBitsToZeroOut) - 1;
        }
        long     resAsLong = ByteBuffer.wrap(m).getLong();*/
        long     resAsLong = toLong(m, numBits);
        byte[]   res = new byte[numChars];
        for (int i=res.length-1; i >= 0; i--) {
            res[i] = (byte) (resAsLong % CHAR_SET_SIZE + 32);
            resAsLong /= CHAR_SET_SIZE;
        }
        return  res;
    }

    /**
     * Converts an arbitrary string of bits represented by {@code m} into a {@code long} value
     */
    private static long  toLong(byte[] m, int numBits) {
        int      numBitsRoundedUp = numBits + 7 & -8,  numBytes = numBitsRoundedUp / 8;
        long     res = 0;
        byte[]   buf = new byte[8];
        for (int j=0; j < m.length; j+=numBytes) {
            System.arraycopy(m, j, buf, 8-numBytes, numBytes);
            res ^= ByteBuffer.wrap(buf).getLong();
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
