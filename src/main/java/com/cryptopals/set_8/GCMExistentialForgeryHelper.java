package com.cryptopals.set_8;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static com.cryptopals.set_8.BooleanMatrixOperations.*;

public final class GCMExistentialForgeryHelper {
    private final PolynomialGaloisFieldOverGF2   group;
    private final PolynomialGaloisFieldOverGF2.FieldElement[]   coeffs;
    private PolynomialGaloisFieldOverGF2.FieldElement[]   forgedCoeffs;
    private final byte[]   cipherTxt;
    private final int     len;
    private boolean[][]   kernel;
    private final boolean[][][]   ms;

    public GCMExistentialForgeryHelper(byte[] cipherText, int plainTextLen) {
        cipherTxt = cipherText;
        len = plainTextLen;
        coeffs = GCM.extractPowerOf2Blocks(cipherTxt, plainTextLen);

        assert coeffs.length > 0;
        group = coeffs[0].group();

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
        List<boolean[]>   verifiedBasis = new ArrayList<>();

        forgedCoeffs = getRandomPowerOf2Blocks();
        boolean[][]   tTransposed = produceDependencyMatrixTransposed();

        kernel = kernelOfTransposed(tTransposed);

        // If the kernel was calculated correctly, for each element d of the kernel the product d * tTransposed = 0.
        // boolean[] expectedProduct = new boolean[tTransposed[0].length], product;

        System.out.println("Extracted kernel length: " + kernel.length);
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

    public PolynomialGaloisFieldOverGF2.FieldElement[] getPowerOf2Blocks() {
        return  coeffs;
    }
    public PolynomialGaloisFieldOverGF2.FieldElement[] getForgedPowerOf2Blocks() {
        return  forgedCoeffs;
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
     * Produces forged power of 2 blocks of the ciphertext using a random element of the kernel of N(tTransposed).
     */
    public PolynomialGaloisFieldOverGF2.FieldElement[]  forgePowerOf2Blocks() {
        // A simple linear congruential pseudo random number generator is good enough here.
        Random rnd = new Random();
        return  forgePowerOf2Blocks(rnd.nextInt(kernel.length));
    }


    /**
     * Produces forged power of 2 blocks of the ciphertext using the {@code kernelElem} element of the kernel of N(tTransposed).
     */
    public PolynomialGaloisFieldOverGF2.FieldElement[]  forgePowerOf2Blocks(int kernelElem) {
        PolynomialGaloisFieldOverGF2.FieldElement[]   adjustedForgedCoeffs = forgedCoeffs./*coeffs.*/clone();

//        System.out.println("\nTaking vector:\n" + Arrays.toString(kernel[kernelElem]));

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

    private boolean[][]  produceDependencyMatrix() {
        boolean[][]  res = new boolean[coeffs.length - 1 << 7][coeffs.length << 7],  ad;

        for (int column=0; column < coeffs.length; column++) {
            for (int b=0; b < 128; b++) {

                // Since other di's are zero matrices, we can calculate ad based on just one di
                ad = calculateAd(column, coeffs[column].add(group.createElement(BigInteger.ONE.shiftLeft(b))) );
                for (int i=0; i < res.length; i++) {
                    res[i][column*128 + b] = ad[i / 128][i % 128];
                }

            }
        }
        return  res;
    }

    private boolean[][]  produceDependencyMatrix2() {
        boolean[][]  res = new boolean[coeffs.length - 1 << 7][coeffs.length << 7],  ad,  adOrig;
        PolynomialGaloisFieldOverGF2.FieldElement[]   newCoeffs = forgedCoeffs.clone();

        for (int column=0; column < coeffs.length; column++) {

            adOrig = calculateAd(forgedCoeffs); // Calculate Ad without D[column]
            adOrig = add(adOrig, calculateAd(column, forgedCoeffs[column]));

            for (int b=0; b < 128; b++) {
                newCoeffs[column] = newCoeffs[column].add(group.createElement(BigInteger.ONE.shiftLeft(b)));

                ad = add(adOrig, calculateAd(column, newCoeffs[column]));

                for (int i=0; i < res.length; i++) {
                    res[i][column*128 + b] = ad[i / 128][i % 128];
                }

                newCoeffs[column] = newCoeffs[column].add(group.createElement(BigInteger.ONE.shiftLeft(b)));
            }
        }
        return  res;
    }

    private boolean[][]  produceDependencyMatrixTransposed() {
        boolean[][]  res = new boolean[coeffs.length << 7][coeffs.length - 1 << 7],  ad,  adOrig;
        PolynomialGaloisFieldOverGF2.FieldElement[]   newCoeffs = forgedCoeffs.clone();

        for (int column=0; column < coeffs.length; column++) {

            adOrig = calculateAd(forgedCoeffs); // Calculate Ad without D[column]
            adOrig = add(adOrig, calculateAd(column, forgedCoeffs[column]));

            for (int b=0; b < 128; b++) {
                newCoeffs[column] = newCoeffs[column].add(group.createElement(BigInteger.ONE.shiftLeft(b)));

                ad = add(adOrig, calculateAd(column, newCoeffs[column]));

                for (int i=0; i < coeffs.length - 1; i++) {
                    System.arraycopy(ad[i], 0, res[column*128 + b], i << 7, 128);
                }

                newCoeffs[column] = newCoeffs[column].add(group.createElement(BigInteger.ONE.shiftLeft(b)));
            }
        }
        return  res;
    }

}
