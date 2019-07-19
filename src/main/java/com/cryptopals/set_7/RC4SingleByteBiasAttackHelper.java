package com.cryptopals.set_7;

import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.IntStream;

/**
 * Created by Andrei Ilchenko on 17-07-19.
 */
public class RC4SingleByteBiasAttackHelper {
    final static private byte[]   ZEROS = new byte[32];
    final static private int   NUM_ITERATIONS_KEY = 1 << 27,  NUM_ITERATIONS = 1 << 24;
    final private double[]   z16Distribution,  z32Distribution;

    @SneakyThrows
    public RC4SingleByteBiasAttackHelper() {
        KeyGenerator rc4KeyGen = KeyGenerator.getInstance("RC4");
        rc4KeyGen.init(128);
        Cipher encryptor = Cipher.getInstance("RC4");
        byte[]   keyStream;
        int[]   z16Ctr = new int[256],  z32Ctr = new int[256];
        for (int i=0; i < NUM_ITERATIONS_KEY; i++) {
            encryptor.init(Cipher.ENCRYPT_MODE, rc4KeyGen.generateKey());
            keyStream = encryptor.doFinal(ZEROS);
            z16Ctr[Byte.toUnsignedInt(keyStream[15])]++;
            z32Ctr[Byte.toUnsignedInt(keyStream[31])]++;
        }

        z16Distribution = Arrays.stream(z16Ctr).mapToDouble(x -> (double) x / NUM_ITERATIONS_KEY).toArray();
        z32Distribution = Arrays.stream(z32Ctr).mapToDouble(x -> (double) x / NUM_ITERATIONS_KEY).toArray();

        System.out.println(Arrays.toString(z16Distribution));
        System.out.println(Arrays.toString(z32Distribution));
    }

    public byte[]  recoverCookie(Function<String, byte[]> oracle, int cookieLen) {
        char   requestTempl[] =  { '/', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };
        byte[]   res = new byte[cookieLen];
        int[]    nVect16 = new int[256],  nVect32 = new int[256];
        double[]  lambda16 = Arrays.stream(new double[256]).map(x -> Double.MIN_VALUE).toArray(),
                  lambda32 = lambda16.clone();

        for (int i=0; i < 16; i++) {
            int[]    c16Ctr = new int[256],  c32Ctr = new int[256];
            String   request = new String(requestTempl, 0, 15 - i);
            byte[]   cipherTxt;
            for (int j = 0; j < NUM_ITERATIONS; j++) {
                cipherTxt = oracle.apply(request);
                c16Ctr[Byte.toUnsignedInt(cipherTxt[15])]++;
                c32Ctr[Byte.toUnsignedInt(cipherTxt[31])]++;
            }
            for (int j=0; j < 1 << 8; j++) { // Assuming printable ASCII characters
                for (int k=0; k < 1 << 8; k++) {
                    nVect16[k] = c16Ctr[j ^ k];
                    nVect32[k] = c32Ctr[j ^ k];
                }
                lambda16[j] = IntStream.range(0, 256).mapToDouble(x -> nVect16[x] * Math.log(z16Distribution[x])).sum();
                lambda32[j] = IntStream.range(0, 256).mapToDouble(x -> nVect32[x] * Math.log(z32Distribution[x])).sum();
            }

            res[i] = (byte) getIndexOfLargest(lambda16);

            if (i + 16 < res.length) {
                res[i + 16] = (byte) getIndexOfLargest(lambda32);
            }
            // Hollywood style
            System.out.println(new String(res));
        }

        return res;

    }

    private static int  getIndexOfLargest(double arr[]) {
        int  res = 0;
        for(int i = 1; i < arr.length; i++) {
            if (arr[i] > arr[res]) {
                res = i;
            }
        }
        return res;
    }
}
