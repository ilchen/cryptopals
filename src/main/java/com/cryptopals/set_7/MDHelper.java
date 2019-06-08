package com.cryptopals.set_7;

import com.cryptopals.Set2;
import com.cryptopals.Set4;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;

/**
 * Created by Andrei Ilchenko on 12-05-19.
 */
public class MDHelper {
    static final Random   SECURE_RANDOM = new SecureRandom(); // Thread safe
    static final int      BLOCK_SIZE = 8;
    private final String   cipher;
    private final Cipher   encryptor;
    private final int   blockSize,  keyLen;
    private final byte[]   H,  H2;

    /**
     * @param H
     * @param cipher  should be a cipher whose key size in bits is a divisor of 512
     * @param keyLen  should be a divisor of 64 (512 bits)
     */
    public MDHelper(byte H[], byte H2[], String cipher, int keyLen) throws NoSuchPaddingException, NoSuchAlgorithmException {
        assert  H2.length > H.length; // otherwise H2 will not result in a more computationally intensive hash
        String   transformation = cipher + "/ECB/NoPadding";
        encryptor = Cipher.getInstance(transformation);
        blockSize = encryptor.getBlockSize();
        this.keyLen = keyLen;
        this.H = H;
        this.H2 = H2;
        this.cipher = cipher;
    }

    /**
     * @param position  the position of the lowest order bit is 0
     */
    private static int  getBit(int i, int position) {
        return  i >> position & 1;
    }

    public byte[]  mdEasy(byte msg[]) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return  md(msg, H);
    }

    public byte[]  mdHard(byte msg[]) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return  md(msg, H2);
    }

    private byte[]  md(byte msg[], byte H[]) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return  md(msg, H, 0);
    }

    private byte[]  md(byte msg[], byte H[], int from) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte   res[][] = mdWithChainVars(msg, H, from);
        return  res[res.length - 1];
    }

    private byte[][]  mdWithChainVars(byte msg[], byte H[]) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return  mdWithChainVars(msg, H, 0);
    }

    private byte[][]  mdWithChainVars(byte msg[], byte H[], int from) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        msg = Set4.mdPad(msg, ByteOrder.BIG_ENDIAN);
        if (msg.length % keyLen != 0) {
            throw  new IllegalArgumentException(
                    String.format("Key len %d is not a divisor of padded message length %d", keyLen, msg.length));
        }

        return  mdInner(msg, H, from, msg.length / keyLen);
    }

    public byte[]  mdInnerLast(byte msg[], byte H[], int from, int to) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        byte   res[][] = mdInner(msg, H, from, to);
        return  res[res.length - 1];
    }

    public byte[]  mdOneBlock(byte msg[], byte H[]) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        encryptor.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(msg, cipher));
        byte   h[] = Arrays.copyOf(encryptor.doFinal(Arrays.copyOf(H, blockSize)), H.length);
        Set2.xorBlock(h, H);
        return  h;
    }

    private byte[][]  mdInner(byte msg[], byte H[], int from, int to) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        assert  from < to;
        assert  to * keyLen <= msg.length;
        byte   res[][] = new byte[to-from][];
        int   j = 0;
        byte[]   _H = H.clone(),  h;
        for (int i=from*keyLen; i < to*keyLen; i+=keyLen) {
            encryptor.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(Arrays.copyOfRange(msg, i, i+keyLen), cipher));
            h = Arrays.copyOf(encryptor.doFinal(Arrays.copyOf(_H, blockSize)), H.length);
            Set2.xorBlock(_H, h);
            res[j++] = _H.clone();
        }

        return  res;
    }

    byte[]  findCollisionWith(byte startingHash[], byte targetHash[])
            throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        byte[]   res = new byte[BLOCK_SIZE],  hash;
        for (int i=0; i < 1 << 16; i++) {
            res[0] = (byte) (i >> 8);
            res[1] = (byte) i;
            hash = mdOneBlock(res, startingHash);
            if (hash[0] == targetHash[0]  &&  hash[1] == targetHash[1]/*Arrays.equals(hash, targetHash)*/) {
                return  res;
            }
        }
        for (int i=1 << 16; i < 1 << 24; i++) {
            res[0] = (byte) (i >> 16);
            res[1] = (byte) (i >> 8);
            res[2] = (byte) i;
            hash = mdOneBlock(res, startingHash);
            if (hash[0] == targetHash[0]  &&  hash[1] == targetHash[1]/*Arrays.equals(hash, targetHash)*/) {
                return  res;
            }
        }
        return  null;
    }

    private byte[]  extractMsg(List<long[]> collisions, int i) {
        ByteBuffer   bb = ByteBuffer.allocate(H2.length << 2 << 3);
        for (int j=0; j < H2.length << 2; j++) {
            bb.putLong(collisions.get(j)[getBit(i, j)]);
        }
        return  bb.array();
    }

    public byte[][]  findCollision() throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        List<long[]>   collisions = findCollisions(H2.length << 2);
        Map<ByteBuffer, Integer>   hashes2Ints = new HashMap<>();
        ByteBuffer   bb = ByteBuffer.allocate(H2.length << 2 + 3);
        for (int i=0; i < 2 << (H2.length << 2); i++) {
            bb.position(0);
            for (int j=0; j < H2.length << 2; j++) {
                bb.putLong(collisions.get(j)[getBit(i, j)]);
            }
            Integer   col = hashes2Ints.put(ByteBuffer.wrap(mdHard(bb.array())), i);
            if (col != null) {
                return  new byte[][] { bb.array(), extractMsg(collisions, col) };
            }
        }
        return  null;
    }

    /**
     * This method assumes {@link #keyLen} is always 8 bytes. It is not trivial to make this method generic in
     * keyLen without losing efficiency.
     */
    private List<long[]>  findCollisions(int n) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        // int   n = Integer.numberOfTrailingZeros(Integer.highestOneBit(n));
        List<long[]>   res = new ArrayList<>(n);
        byte[]   i1 = new byte[0],  i2 = new byte[0],  hash = H;
        for (int i=0; i < n; i++) {
            i1 = Arrays.copyOf(i1, Long.BYTES * (i + 1));
            i2 = Arrays.copyOf(i2, Long.BYTES * (i + 1));
            ByteBuffer   bb1 = ByteBuffer.wrap(i1),  bb2 = ByteBuffer.wrap(i2);
            NEXT_PAIR:
            for (long l1=0; l1 < Short.MAX_VALUE; l1++) {
                for (long l2=l1+1; l2 < Short.MAX_VALUE + 1L; l2++) {
                    bb1.position(Long.BYTES * i);
                    bb2.position(Long.BYTES * i);
                    bb1.putLong(l1);    bb2.putLong(l2);
                    if (Arrays.equals(mdInner(i1, hash, i, i+1)[0], mdInner(i2, hash, i, i+1)[0])) {
                        System.out.printf("Found collision for %d and %d%n", l1, l2);
                        res.add(new long[] {  l1,  l2  });
                        hash = mdInner(i1, hash, i, i+1)[0];
                        break  NEXT_PAIR;
                    }
                }
            }

        }
        assert  i1.length == Long.BYTES * n;
        assert  Arrays.equals(mdEasy(i1), mdEasy(i2));
        return  res;
    }

    /** Finds two messages of length 1 and 2^(k-1)+1 blocks whose md hashes collide */
    public byte[][] findCollision(int k) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        int      n = 1 << k - 1;
        byte[]   i1 = new byte[Long.BYTES],  i2 = new byte[Long.BYTES * (n + 1)],  hash,  innerHash;
        ByteBuffer   bb1 = ByteBuffer.wrap(i1),  bb2 = ByteBuffer.wrap(i2);
        for (int i=0; i < n; i++) {
            bb2.putLong(SECURE_RANDOM.nextLong());
        }

        // A small lookup table to speed things up
        Map<Integer, Long>   lookupTable = new HashMap<>();
        for (long l1=0; l1 <= Short.MAX_VALUE; l1++, bb1.position(0)) {
            bb1.putLong(l1);
            hash = mdInnerLast(i1, H, 0, 1);
            lookupTable.put((hash[0] << 8) + (hash[1] & 0xff), l1);
        }

        // Another optimization recommended in the Challenge
        innerHash = mdInner(i2, H, 0, n)[n-1];
        for (long l2=0; l2 <= Short.MAX_VALUE + 1L; l2++) {
            bb2.putLong(l2);
            hash = mdInnerLast(i2, innerHash, n, n+1);
            Long   l1 = lookupTable.get((hash[0] << 8) + (hash[1] & 0xff));
            if (l1 != null) {
                bb1.putLong(l1);
                System.out.printf("Found collision for %d and %d%n", l1, l2);
                assert  Arrays.equals(mdInnerLast(i1, H, 0, 1), mdInnerLast(i2, H, 0, n+1));
                return  new byte[][] {  i1,  i2,  hash  };
            }
            bb2.position(Long.BYTES * n);
        }

        return  null;
    }

    private static byte[][][]  buildExpandableMessage(final int k, byte hash[], final byte H2[],
                                                      final String cipher, final int keyLen)
            throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        byte   res[][][] = new byte[k][][];
        int   i = 0;
        while (i < k) {
            res[i] = new MDHelper(hash, H2, cipher, keyLen).findCollision(k - i);
            hash = res[i++][2];
        }
        return  res;
    }

    public byte[]  find2ndPreimage(byte msg[]) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        // Assuming an 8 byte block
        byte   hashes[][] = mdWithChainVars(msg, H),  expandableMessage[][][];
        int    i,  k = Integer.numberOfTrailingZeros(msg.length >>> 3);
        do {
            expandableMessage = buildExpandableMessage(k, H, H2, cipher, keyLen);
            for (i=0; i < 1 << k; i++) {
/*                System.out.printf("\t0x%04x: 0x%02x%02x and 0x%02x%02x%n", i, hashes[i][0], hashes[i][1],
                        expandableMessage[expandableMessage.length - 1][2][0],
                        expandableMessage[expandableMessage.length - 1][2][1]);*/
                if (Arrays.equals(hashes[i], expandableMessage[expandableMessage.length - 1][2])) {
                    System.out.printf("Bridge found with hash index %d%nhash = 0x%s%n",
                            i, DatatypeConverter.printHexBinary(hashes[i]));
                    break;
                }
            }
            if (i == 1 << k)  System.out.println("Going round");
        } while (i == 1 << k);

        byte[]   res = new byte[msg.length],  prefixPart;
        final int      remainingLen = i + 1 << 3,  T = i + 1 - k;

        // Copying msg[i..]
        System.arraycopy(msg, remainingLen, res, remainingLen, msg.length - remainingLen);

        // Copying the prefix and the bridge
        for (int j=0, offset=0; j < expandableMessage.length; j++) {
            // prefixPart = expandableMessage[j][1].length <= remainingLen - (expandableMessage.length - 1 - j << 3)

            // See Page 8 of the paper: https://www.schneier.com/academic/paperfiles/paper-preimages.pdf
            prefixPart = getBit(T, expandableMessage.length - 1 - j) == 1  ?  expandableMessage[j][1]
                                                                                   :  expandableMessage[j][0];
            System.arraycopy(prefixPart, 0, res, offset, prefixPart.length);
            offset += prefixPart.length;
            // remainingLen -= prefixPart.length;
        }
        return  res;
    }

}
