package com.cryptopals.set_7;

import com.cryptopals.Set2;
import com.cryptopals.Set4;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Created by Andrei Ilchenko on 12-05-19.
 */
public class MDHelper {
    private final String   cipher;
    private final Cipher   encryptor;
    private final int   blockSize,  keyLen;
    private final byte[]   H,  H2;

    /**
     * @param H
     * @param cipher  should be a cipher whose key size in bits is a divisor of 512
     * @param keyLen  should be a divisor of 64 (512 bits)
     */
    public MDHelper(byte H[], byte H2[],String cipher, int keyLen) throws NoSuchPaddingException, NoSuchAlgorithmException {
        assert  H2.length > H.length; // otherwise H2 will not result in a more computationally intensive hash
        String   transformation = cipher + "/ECB/NoPadding";
        encryptor = Cipher.getInstance(transformation);
        blockSize = encryptor.getBlockSize();
        this.keyLen = keyLen;
        this.H = H;
        this.H2 = H2;
        this.cipher = cipher;
    }

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
        int  outputSize = H.length;
        byte[]   _H = H.clone(),  h;
        msg = Set4.mdPad(msg, ByteOrder.BIG_ENDIAN);
        if (msg.length % keyLen != 0) {
            throw  new IllegalArgumentException(
                    String.format("Key len %d is not a divisor of padded message length %d", keyLen, msg.length));
        }

        for (int i=0; i < msg.length; i+=keyLen) {
            encryptor.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(Arrays.copyOfRange(msg, i, i+keyLen), cipher));
            h = Arrays.copyOf(encryptor.doFinal(Arrays.copyOf(_H, blockSize)), outputSize);
            Set2.xorBlock(_H, h);
        }

        return  _H;
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
        byte[]   i1 = new byte[0],  i2 = new byte[0];
        for (int i=0; i < n; i++) {
            i1 = Arrays.copyOf(i1, Long.BYTES * (i + 1));
            i2 = Arrays.copyOf(i2, Long.BYTES * (i + 1));
            ByteBuffer   bb1 = ByteBuffer.wrap(i1),  bb2 = ByteBuffer.wrap(i2);
            NEXT_PAIR:
            for (long l1=0; l1 < Short.MAX_VALUE; l1++) {
                for (long l2=l1+1; l2 < Short.MAX_VALUE + 1L; l2++) {
                    bb1.putLong(l1);    bb2.putLong(l2);
                    if (Arrays.equals(mdEasy(i1), mdEasy(i2))) {
                        System.out.printf("Found collision for %d and %d%n", l1, l2);
                        res.add(new long[] {  l1,  l2  });
                        break  NEXT_PAIR;
                    }
                    bb1.position(Long.BYTES * i);
                    bb2.position(Long.BYTES * i);
                }
            }

        }
        assert  i1.length == Long.BYTES * n;
        assert  Arrays.equals(mdEasy(i1), mdEasy(i2));
        return  res;
    }
}
