package com.cryptopals.set_8;

import com.cryptopals.Set8;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.UnaryOperator;

import static com.cryptopals.set_8.BooleanMatrixOperations.*;

/**
 * Implements the logic for an attack on applications of GCM with a small authentication tag size as outlined
 * in the <a href="https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf">
 * Authentication weaknesses in GCM</a> paper published by Niels Ferguson in 2005. The implementation efficiently
 * handles the case when the ciphertext is not a multiple of blocksize, which requires manipulating the block
 * that encodes the length of associated data and plaintext.
 */
public final class GCMExistentialForgeryHelper {
    private static final int   BLOCK_SIZE = 0x10,  BLOCK_MASK = 0x0f;
    private final PolynomialGaloisFieldOverGF2   group;
    private final PolynomialGaloisFieldOverGF2.FieldElement[]   coeffs;
    private final UnaryOperator<byte[]>   gcmFixedKeyAndNonceDecipherOracle;
    private final Set8.GcmFixedKeyAndNonceErrorPolynomialOracle   gcmFixedKeyAndNonceErrorPolynomialOracle;
    private final int   plainTextLen,  tLen;
    private PolynomialGaloisFieldOverGF2.FieldElement[]   forgedCoeffs;
    private final byte[]   cipherTxt;
    private byte[]   forgedCipherTxt;
    private final List<boolean[]>   K;
    private PolynomialGaloisFieldOverGF2.FieldElement   h;
    private boolean[][]   kernel;
    private boolean[][]   X;    /* Non-null if at least 16 bits of authentication key have been recovered */
    private final PolynomialGaloisFieldOverGF2.FieldElement   d0;   /* T * d = d0, not-null if plaintext is not a multiple of the blocksize */
    private final boolean[][]   Ad0; /* Non-null if plaintext is not a multiple of the blocksize */
    private final boolean[][][]   ms;

    /**
     * Constructs a new instance of this class
     * @param cipherText  a legit ciphertext
     * @param plnTxtLen  the length of the plaintext whose encryption is captured in {@code ciphertext}
     * @param tagLen  the length of GCM authentication tag
     * @param oracle  a decryption oracle that will decrypt pieces of ciphertext with the same key and nonce
     *                as those that were used to encrypt the plaintext into {@code copherText}
     * @param errorPolynomialOracle   an oracle that will be used to calculate the error polynomial, not needed for
     *                                the attack per see but makes it run faster as calculating the error polynomial
     *                                is faster than deciphering the entire ciphertext
     */
    public GCMExistentialForgeryHelper(byte[] cipherText, int plnTxtLen, int tagLen, UnaryOperator<byte[]> oracle,
                                       Set8.GcmFixedKeyAndNonceErrorPolynomialOracle errorPolynomialOracle) {
        cipherTxt = cipherText;
        coeffs = GCM.extractPowerOf2Blocks(cipherTxt, plnTxtLen);
        plainTextLen = plnTxtLen;
        tLen = tagLen;
        gcmFixedKeyAndNonceDecipherOracle = oracle;
        gcmFixedKeyAndNonceErrorPolynomialOracle = errorPolynomialOracle;
        K = new ArrayList<>();

        assert coeffs.length > 0;
        group = coeffs[0].group();

        if ((plnTxtLen & BLOCK_MASK) != 0) {
            // We are expanding the size of the ciphertext without the authentication tag to be multiple of blocksize.
            // This will create a non-zero difference between C0 and C'0 (the blocks encoding the length of associated data and plaintext.
            int   paddedPlnTextLen = (plnTxtLen | ~(plnTxtLen & BLOCK_MASK) & BLOCK_MASK) + 1;
            ByteBuffer   lengthBuf = ByteBuffer.allocate(BLOCK_SIZE).order(ByteOrder.BIG_ENDIAN)
                    .putLong(0).putLong(plnTxtLen * Byte.SIZE);
            PolynomialGaloisFieldOverGF2.FieldElement   c0 = GCM.toFE(lengthBuf.array());
            lengthBuf.position(Long.BYTES);
            lengthBuf.putLong(paddedPlnTextLen * Byte.SIZE);
            Ad0 = (d0 = c0.subtract(GCM.toFE(lengthBuf.array()))).asMatrix();
        }  else  {
            Ad0 = null;     d0 = null;
        }

        ms = new boolean[coeffs.length][][];
        ms[0] = group.getSquaringMatrix();
        for (int i=1; i < coeffs.length; i++) {
            ms[i] = multiply(ms[i-1], ms[0]);
        }

        replaceBasis();
    }

    /**
     * Calculates new random 2<sup>i</sup>th blocks of ciphertext, derives a dependency matrix and its kernel.
     */
    public void  replaceBasis() {
        boolean[][]   tTransposed;
        // Determining dimensions of the dependency matrix
        int   ncolsX = X == null  ?  128
                                  :  X[0].length,
              // If the last block of plaintext is not of a full blocksize, Ad0 != 0. In this case I need to zero out
              // {@code coeffs.length} rows of Ad.
              //
              // If we have n*128 bits to play with, we can zero out (n*128) / (ncols(X)) rows of Ad.
              // Just remember to leave at least one nonzero row in each attempt; otherwise you won'd0 learn anything new.
              m = X == null  ?  coeffs.length - (Ad0 == null  ?  1 : 0) << 7
                             :  Ad0 == null  ?  Math.min((coeffs.length << 7) / ncolsX, (tLen - 1)) * ncolsX : coeffs.length << 7,
              mReduced = X == null  ?  coeffs.length - 1 << 7 : Math.min((coeffs.length << 7) / ncolsX, (tLen - 4)) * ncolsX;

        forgedCoeffs = getRandomPowerOf2Blocks();
        tTransposed = produceDependencyMatrixTransposed(ncolsX, m);

        if (Ad0 != null) { /* We need to solve for T * d = t */
            int   rank;
            boolean[]   t = new boolean[m];
            boolean   d[];

            boolean[][]   T = transpose(tTransposed),  AdX = calculateAd(forgedCoeffs),  Ad0X = Ad0;
            if (X != null) {
                AdX = multiply(AdX, X);
                Ad0X = multiply(Ad0, X);
            }
            for (int i = 0; i < m; i++) {
                // t is the nonzero difference in the first n rows of AdX induced by our tweak to the length block.
                t[i] = AdX[i / ncolsX][i % ncolsX] ^ Ad0X[i / ncolsX][i % ncolsX];
            }

            boolean[][]   tWithCol = appendColumn(T, t);
            rank = gaussianElimination(tWithCol, tTransposed.length, null, true);
            //System.out.printf("Maximum possible rank: %d%nActual rank: %d%n", T.length, rank);

            d = extractColumn(tWithCol, tTransposed.length);
            if (rank < T.length) {
                // It is still possible for T, t to be consistent if the dependent row of T have the same values in t
                int h = 0, k = 0;
                while (h < tWithCol.length && k < tWithCol.length) {
                    if (tWithCol[h][k]) {
                        d[k] = tWithCol[h][tTransposed.length];
                        h++;     k++;
                    } else {
                        d[k] = false;
                        k++;
                    }
                }
            }
            if (mReduced < m) {
                tTransposed = copy(tTransposed, mReduced);
            }
            boolean[][]   preKernel = kernelOfTransposed(tTransposed);
            kernel = new boolean[preKernel.length + 1][];
            kernel[0] = d;

            for (int i=0; i < preKernel.length; i++) {
                kernel[i + 1] = add(preKernel[i], d);
            }

        }  else  kernel = kernelOfTransposed(tTransposed);
        // System.out.printf("Kernel size: %d%n", kernel.length);

        // If the kernel was calculated correctly, for each element d of the kernel the product d * tTransposed = 0.
        // boolean[] expectedProduct = new boolean[tTransposed[0].length], product;

//        System.out.println("Extracted kernel length: " + kernel.length);
//        for (boolean[] d : kernel) {
//            product = multiply(d, tTransposed);
//            assert  Arrays.equals(product, expectedProduct)
//        }
    }

    /**
     * Calculates AD based on all d<sup>i</sup> block of ciphertext differences
     */
    public boolean[][]  calculateAd(PolynomialGaloisFieldOverGF2.FieldElement[] forgedCoeffs) {
        assert coeffs.length == forgedCoeffs.length;
        boolean[][]  res = multiply(coeffs[0].subtract(forgedCoeffs[0]).asMatrix(), ms[0]);
        for (int i=1; i < coeffs.length; i++) {
            res = add(res, multiply(coeffs[i].subtract(forgedCoeffs[i]).asMatrix(), ms[i]));
        }
        return  res;
    }

    /**
     * Calculates AD based on just one modified 2<sup>i</sup>th block of ciphertext differences
     * @param i  indicate which of d<sub>i</sub> blocks to use, {@code i==0} represents d<sub>1</sub>.
     */
    private boolean[][]  calculateAd(int i, PolynomialGaloisFieldOverGF2.FieldElement forgedCoeff) {
        assert coeffs.length > i;
        return  multiply(coeffs[i].subtract(forgedCoeff).asMatrix(), ms[i]);
    }

    /**
     * The main method of this class. In the outer loop it iterates over different random choices for forged coefficients
     * waiting for a success in forging such coefficients that the last {@code tLen} bits of the error polynomial are
     * zero. With each such success, the method learns a few new bits about the authentication key. The method finishes
     * after all 128 bits of the authentication key have been recovered.
     */
    public void  recoverAuthenticationKey() {
        // Attempt at an existential forgery
        boolean[]  expectedBits = new boolean[tLen/2],   requiredBits = new boolean[tLen],  zeroAdRow = new boolean[128],  tag;
        byte[]     forgedCtxt,  plainTxt;
        int        count = 0;

        System.out.println("Search for the authentication key started");
        K_COMPLETE:
        while (true) {
            for (int i=0; i < kernel.length; i++) {
                PolynomialGaloisFieldOverGF2.FieldElement[] coeffsPrime = forgePowerOf2Blocks(i);

                // The majority of d's that we extract from the kernel will zero out the tLen/2 low-order
                // bits of GHASH, however we need to rely on trial and error to get all tLen low-order bits
                // to be zero.
                tag = gcmFixedKeyAndNonceErrorPolynomialOracle.ghashPower2BlocksDifferences(coeffs, coeffsPrime, d0).asVector();
                      //gcm.ghashPower2BlocksDifferences(coeffs, coeffsPrime, d0).asVector();

                // Check if the first tLen/2 bits of the tag are indeed zero. For some reason this test passes for
                // about half the elements of the kernel.
                if (Arrays.equals(Arrays.copyOf(tag, expectedBits.length), expectedBits)) {
                    // Only counting as attempts when we correctly zeroed out the leftmost tLen/2 bits.
                    count++;
                } else  continue;

                if (!Arrays.equals(Arrays.copyOf(tag, requiredBits.length), requiredBits)) continue;

                forgedCtxt = GCM.replacePowerOf2Blocks(cipherTxt, plainTextLen, coeffsPrime, true);
                plainTxt = gcmFixedKeyAndNonceDecipherOracle.apply(forgedCtxt);
                if (plainTxt != null) {
                    boolean[][] ad = calculateAd(coeffsPrime),  adAdj,  Xcand;
                    if (Ad0 != null)  ad = add(ad, Ad0);
                    if (X != null) { /* We already know at least tLen/2 bits of information about h */
                        adAdj = multiply(ad, X);
                        zeroAdRow = new boolean[X[0].length];
                    } else  adAdj = ad;

                    System.out.printf(" Attempt %4d. Success with existential forgery. Error polynomial: %s%nFirst KB of plaintext:%n%s%n",
                            count, group.createElement(tag), new String(plainTxt, 0, 1024));
                    // Assuming the some of the next tLen/2 rows of Ad·X are not zero, we have gained information about
                    // additional bits of the authentication key (each non-zero row reveals a new bit).
                    for (int j = expectedBits.length; j < tLen; j++) {
                        // Rows that are zero don'd0 reveal anything about h, so ignoring them
                        if (!Arrays.equals(zeroAdRow, adAdj[j]))  K.add(ad[j]);
                    }

                    forgedCoeffs = coeffsPrime;
                    forgedCipherTxt = forgedCtxt;

                    // It turns out not to be needed, the above check for non-zero rows in Ad·X takes care of no
                    // linearly dependent vectors ending up in K.
                    removeLinearlyDependentVectors(K);

                    // K [16x128], X [128x112]
                    Xcand = transpose(kernel((K.size() > 127  ?  K.subList(0, 127) : K).toArray(new boolean[Math.min(K.size(), 127)][])));
                    if (Xcand[0].length == 1)  {
                        // K has 127 linearly independent equations
                        break K_COMPLETE;
                    }

                    // Special case when plaintext is not a multiple of blocksize. We need to have enough elements in X to solve Ad*X*h = t.
                    // This requires that the second dimension of X be as large as coeffs.length. However that will likely lead to us
                    // zeroing out many more bits of the error polynomial than tLen. Since the Oracle only tells us whether
                    // we correctly zeroed out he tLen ones, we cannot assuredly rely on the other bit being zeroed out, even
                    // though it is likely the case. To combat that I refrain from shrinking the second dimension of X that is
                    // used in constructing the dependency matrix further than thrice the number of coefficients we can play with.
                    if (Ad0 == null  ||  Xcand[0].length >= coeffs.length * 3) {
                        X = Xcand;
                    }
                    System.out.printf("Size of K: %d, rank of K: %d%n", K.size(), 128 - Xcand[0].length);

                    break;
                }
            }
            replaceBasis();
        }

        boolean[][]  k = kernel(K.toArray(new boolean[K.size()][]));
        h = group.createElement(k[0]);

    }

    public PolynomialGaloisFieldOverGF2.FieldElement[] getPowerOf2Blocks() {
        return  coeffs;
    }
    public PolynomialGaloisFieldOverGF2.FieldElement[] getForgedPowerOf2Blocks() {
        return  forgedCoeffs;
    }
    public byte[] getForgedCiphertext() {
        return  forgedCipherTxt;
    }
    public PolynomialGaloisFieldOverGF2.FieldElement getRecoveredAuthenticationKey() {
        return  h;
    }

    public PolynomialGaloisFieldOverGF2.FieldElement[] getRandomPowerOf2Blocks() {
        PolynomialGaloisFieldOverGF2.FieldElement[]   coeffsPrime = new PolynomialGaloisFieldOverGF2.FieldElement[coeffs.length];
        // We start by replacing with random elements of GF(2^128)
        for (int i=0; i < coeffs.length; i++) {
            coeffsPrime[i] = coeffs[0].getRandomElement();
        }
        return  coeffsPrime;
    }

    private  PolynomialGaloisFieldOverGF2.FieldElement[]  toFieldElements(boolean[] d) {
        assert  (d.length & 0x7f) == 0;
        PolynomialGaloisFieldOverGF2.FieldElement[]   res = new PolynomialGaloisFieldOverGF2.FieldElement[d.length >> 7];
        for (int i=0; i < res.length; i++) {
            res[i] = group.createElement(Arrays.copyOfRange(d, i << 7, i + 1 << 7));
        }
        return  res;
    }

    /**
     * Produces forged power of 2 blocks of the ciphertext using the {@code kernelElem} element of the kernel of N(tTransposed).
     */
    public PolynomialGaloisFieldOverGF2.FieldElement[]  forgePowerOf2Blocks(int kernelElem) {
        PolynomialGaloisFieldOverGF2.FieldElement[]   adjustedForgedCoeffs = forgedCoeffs./*coeffs.*/clone();

        for (int column=0; column < coeffs.length; column++) {
            PolynomialGaloisFieldOverGF2.FieldElement   el =
                    group.createElement(Arrays.copyOfRange(kernel[kernelElem], column << 7, column + 1 << 7));
//            System.out.printf("%s%n^%n%s%n=%n", adjustedForgedCoeffs[column], el);
            adjustedForgedCoeffs[column] = adjustedForgedCoeffs[column].add(el);  /* Flipping the right bits */
//            System.out.println(adjustedForgedCoeffs[column] + "\n");
        }
        return  adjustedForgedCoeffs;
    }

    public boolean[][] getKernel() {
        return kernel;
    }

    /**
     * Calculates a dependency matrix to zero out the first {@code tLen/2} rows of A<sub>d</sub> or
     * the first min(tLen -1, 128·{@code coeffs.length} / ncols(X)) rows of  A<sub>d</sub>·X.
     * @param ncolsX  number of columns in Ad·X or in Ad if {@code X == null}
     * @param m  number of rows in the not-transposed dependency matrix
     */
    private boolean[][]  produceDependencyMatrixTransposed(int ncolsX, int m) {
        int   numAdXrowsToZeroOut = Math.min(128, m / ncolsX);

        // 'res' contains a transposed dependency matrix
        boolean[][]  res = new boolean[coeffs.length << 7][m],  ad,  adOrig;
        PolynomialGaloisFieldOverGF2.FieldElement[]   newCoeffs = forgedCoeffs.clone();

        for (int column=0; column < coeffs.length; column++) {

            adOrig = calculateAd(forgedCoeffs); // Calculate Ad without D[column]
            adOrig = add(adOrig, calculateAd(column, forgedCoeffs[column]));

            for (int b=0; b < 128; b++) {
                newCoeffs[column] = newCoeffs[column].add(group.createElement(BigInteger.ONE.shiftLeft(b)));

                ad = add(adOrig, calculateAd(column, newCoeffs[column]));
                if (X != null) { /* We already recovered at least tLen/2 bits of the authentication key */
                    // Ad [128x128] x X [128x112]
                    ad = multiply(ad, X);
                }

                for (int i=0; i < numAdXrowsToZeroOut; i++) {
                    System.arraycopy(ad[i], 0, res[column*128 + b], i * ncolsX, ncolsX);
                }

                newCoeffs[column] = newCoeffs[column].add(group.createElement(BigInteger.ONE.shiftLeft(b)));
            }
        }
        return  res;
    }

}
