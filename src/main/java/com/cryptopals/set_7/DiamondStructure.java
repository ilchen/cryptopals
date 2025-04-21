package com.cryptopals.set_7;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;

/**
 * This class uses a four dimensional array to represent the diamond structure from:
 * <a href="https://eprint.iacr.org/2005/281.pdf">this paper</a>
 *
 * <p>The first dimension (i) is the tree level, the second (j) contains 2^(k-i) [][] arrays in which the first dimension
 * is the starting hash h[i, j] and the second is a message block that collides with that of the message starting
 * at either h[i, j+1] or h[i, j-1].</p>
 *
 * <p>Created by Andrei Ilchenko on 02-06-19.</p>
 */
public class DiamondStructure {
    private class LevelRangeBuilder implements Callable<Void> {
        private final int  start,  end,  i;
        private final MDHelper   mdh;

        /**
         * @param jStart  index into the second dimension of the diamond structure (inclusive)
         * @param jEnd  exclusive
         */
        LevelRangeBuilder(int i, int jStart, int jEnd) throws NoSuchAlgorithmException, NoSuchPaddingException {
            this.i = i;
            start = jStart;     end = jEnd;
            mdh = new MDHelper(new byte[targetHash.length], new byte[targetHash.length + 1], cipher, keyLen);
        }

        @Override
        public Void  call() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
            assert  (end - start & 0x1) == 0 : "The range doesn't contain an even number of elements";
            System.out.printf("Worker %s starts populating range [%d, %d]%n", Thread.currentThread().getName(), start, end);
            for (int j=start; j < end; j++) {
                if (j % 2 == 0) {
                    diamondStructure[i][j][1] = new byte[keyLen];
                    ThreadLocalRandom.current().nextBytes(diamondStructure[i][j][1]); // No need for SecureRandom here
                    diamondStructure[i+1][j >> 1] = new byte[2][];
                    diamondStructure[i+1][j >> 1][0] =
                            mdh.mdOneBlock(diamondStructure[i][j][1], diamondStructure[i][j][0]);
                } else {
                    diamondStructure[i][j][1] = mdh.findCollisionWith(diamondStructure[i][j][0], diamondStructure[i+1][j >> 1][0]);
                    assert diamondStructure[i][j][1] != null : "Happened for [%d][%d][1]%n".formatted(i, j);
                }
            }
            return  null;
        }
    }

    private final byte   diamondStructure[][][][],  targetHash[];
    private final String   cipher;
    private final int      keyLen;
    /** This is the easiest way to do a binary search on the hashes stored at the leaves */
    private final List<byte[]>   listView = new AbstractList<>() {
        @Override
        public byte[] get(int index) {
            return diamondStructure[0][index][0];
        }

        @Override
        public int size() {
            return diamondStructure[0].length;
        }
    };

    public DiamondStructure(final int k, byte trgtHash[], final String cipher, final int keyLen)
            throws NoSuchPaddingException, NoSuchAlgorithmException, ExecutionException, InterruptedException,
                   BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        assert k <= 16 : "k too large: " + k;
        diamondStructure = new byte[k][][][];
        this.cipher = cipher;
        this.keyLen = keyLen;
        targetHash = trgtHash;
        int   concurrency = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        try {
            List<Future<Void>> futures = new ArrayList<>(concurrency);

            // Populating the first h[0, j]. The population of the elements h[0, j, 0] is done in such as way
            // as to ensure that they are sorted.
            byte h[] = new byte[trgtHash.length];
            diamondStructure[0] = new byte[1 << k][][];
            for (int j = 0; j < 1 << k; j++) {
                h[0] = (byte) (j >> 8);
                h[1] = (byte) j;
                diamondStructure[0][j] = new byte[2][];
                diamondStructure[0][j][0] = h.clone();
            }

            for (int i=0; i < k - 1; i++) {
                diamondStructure[i + 1] = new byte[1 << k - i - 1][][];
                int step = (1 << k - i) / concurrency;

                if (1 << k - i > concurrency << 2) {
                    for (int j=0; j < 1 << k - i; j += step) {
                        futures.add(executor.submit(new LevelRangeBuilder(i, j, j + step)));
                    }

                    for (Future<Void> future : futures) {
                        future.get();/* This should also take care of safe publication of updates to diamondStructure */
                    }
                } else {               /* The current thread will do */
                    new LevelRangeBuilder(i, 0, 1 << k - i).call();
                }
            }

            // Deal with the last level
            MDHelper   mdh = new MDHelper(new byte[targetHash.length], new byte[targetHash.length+1], cipher, keyLen);
            diamondStructure[k - 1][0][1] = mdh.findCollisionWith(diamondStructure[k - 1][0][0], targetHash);
            diamondStructure[k - 1][1][1] = mdh.findCollisionWith(diamondStructure[k - 1][1][0], targetHash);

            System.out.println("Diamond structure constructed");
        } finally {
            executor.shutdown();
        }

    }

    public byte[]  constructSuffix(byte hash[]) {
        // here we take advantage of the fact that the hashes in diamondStructure[0][j][0] are sorted
        int   idx = Collections.binarySearch(listView, hash, (o1, o2) -> {
            int  len = Math.min(o1.length, o2.length);
            for (int i=0; i < len; i++) {
                int   a = o1[i] & 0xff,  b = o2[i] & 0xff;
                if (a != b) {
                    return  a - b;
                }
            }
            return o1.length - o2.length;
        });
        if (idx < 0) {
            System.out.println("The correct index would be " + idx);
            return  null;
        }
        ByteBuffer   bb = ByteBuffer.allocate(diamondStructure.length * keyLen);

        for (int i=0; i < diamondStructure.length; i++, idx >>= 1) {
            bb.put(diamondStructure[i][idx][1]);
        }

        return  bb.array();
    }
}
