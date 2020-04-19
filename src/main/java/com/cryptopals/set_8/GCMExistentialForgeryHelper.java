package com.cryptopals.set_8;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static com.cryptopals.set_8.BooleanMatrixOperations.*;
import static java.math.BigInteger.valueOf;

public final class GCMExistentialForgeryHelper {
    private final PolynomialGaloisFieldOverGF2   group;
    private final PolynomialGaloisFieldOverGF2.FieldElement[]   coeffs;
    private final byte[]   cipherTxt;
    private final int   len;
    private final boolean[][]   T,  basis;
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

        // Calculate a dependency matrix T [2048x2176]
        T = produceDependencyMatrix();

        // Calculate a basis of N(T)
        // Tt [2176x2048],  tmp [2176x(2048+2176)] = [2176x4224]
        // What you want to do is transpose T (i.e. flip it across its diagonal)
        boolean[][]  Tt = transpose(T);

        // ... and find the reduced row echelon form using Gaussian elimination. Now perform the
        // same operations on an identity matrix of size n*128.

        // Doing it in one go by using only the columns of T transposed during Gaussian elimination
        boolean[][]  tmp = appendIdentityMatrix(Tt);
        gaussianElimination(tmp, T.length);

        // If the basis was calculated correctly, for each element d of the basis, the product T * d = 0.
        boolean[]         expectedProduct = new boolean[T.length],  product;
        List<boolean[]>   verifiedBasis = new ArrayList<>();
        tmp = extractBasisMatrix(tmp);

        System.out.println("\n\nExtracted basis length: " + tmp.length);

        for (boolean[] d : tmp) {
            product = multiply(T, d);
            if (Arrays.equals(product, expectedProduct)) {
                verifiedBasis.add(d);
            }
        }

        basis = verifiedBasis.toArray(new boolean[verifiedBasis.size()][]);
        assert  basis.length > 0;
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
     * Produces forged power of 2 blocks of the ciphertext using a random element of the basis of N(T).
     */
    public PolynomialGaloisFieldOverGF2.FieldElement[]  forgePowerOf2Blocks() {
        PolynomialGaloisFieldOverGF2.FieldElement[]   forgedCoeffs = coeffs.clone();

        // A simple linear congruential pseudo random number generator is good enough here.
        Random rnd = new Random();
            boolean[]   d = basis[rnd.nextInt(basis.length)];

        System.out.println("\nTaking vector:\n" + Arrays.toString(d));

        for (int column=0; column < coeffs.length; column++) {
            PolynomialGaloisFieldOverGF2.FieldElement   el =
                    group.createElement(Arrays.copyOfRange(d, column << 7, column + 1 << 7));
            System.out.printf("%s%n^%n%s%n=%n", forgedCoeffs[column], el);
            forgedCoeffs[column] = forgedCoeffs[column].add(el);  /* Flipping the right bits */
            System.out.println(forgedCoeffs[column] + "\n");
        }
        return  forgedCoeffs;
    }

    public boolean[][]  getDependencyMatrix() {
        //return  copy(T);
        return  T;
    }

    public boolean[][]  getBasis() {
        return  basis;
    }

    private boolean[][]  produceDependencyMatrix() {
        boolean[][]  res = new boolean[coeffs.length - 1 << 7][(coeffs.length << 7)],  ad;

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

}
