package com.cryptopals.set_8;

import java.util.Arrays;
import java.util.List;

/**
 * Implements matrix operations over GF(2).
 */
public class BooleanMatrixOperations {
    public static boolean[][]  copy(boolean[][] mat) {
        int   m = mat.length,  n = mat[0].length;
        boolean[][]   res = new boolean[m][n];
        for (int i=0; i < m; i++) {
            System.arraycopy(mat[i], 0, res[i], 0, n);
        }
        return  res;
    }

    public static void transposeInPlace(boolean[][] m) {
        for (int i=0; i < m.length; i++) {
            for (int j=i+1; j < m.length; j++) {
                boolean   tmp = m[i][j];
                m[i][j] = m[j][i];
                m[j][i] = tmp;
            }
        }
    }

    public static boolean[][]  transpose(boolean[][] mat) {
        int   m = mat.length,  n = mat[0].length;
        boolean[][]   res = new boolean[n][m];
        for (int i=0; i < m; i++) {
            for (int j=0; j < n; j++) {
                res[j][i] = mat[i][j];
            }
        }
        return  res;
    }

    public static int  gaussianElimination(boolean[][] mat, boolean[][] identMat) {
        return  gaussianElimination(mat, mat[0].length, identMat);
    }

    /**
     * Computes a row echelon form of {@code mat} by Gaussian elimination. The algorithm is an adaptation
     * of <a href="https://en.wikipedia.org/wiki/Gaussian_elimination#Pseudocode">this algorithm</a> for GF(2).
     * A similar algorithm albeit with a small omission can be found in
     * <a href="http://www.hyperelliptic.org/tanja/SHARCS/talks06/smith_revised.pdf">this paper</a>.
     *
     * @param mat  a matrix that will modified in place
     * @param n  the number of columns to use when applying Gaussian elimination
     * @param identMat  an optional identity matrix, can be {@code null}. If provided, it will be modified in place
     *                  as though its rows were appended to the right of {@code mat}
     * @return  the rank of {@code mat}
     */
    public static int  gaussianElimination(boolean[][] mat, int n, boolean[][] identMat) {
        if (n > mat[0].length)  throw  new IllegalArgumentException("n is too high: " + n);
        if (identMat != null  &&  mat.length != identMat.length)
            throw  new IllegalArgumentException(
                    String.format("Dimentions of mat and identity matrix don't match: %d vs %d", mat.length, identMat.length));
        int   m = mat.length,  nFull = mat[0].length,  h = 0,  k = 0,  iMax;
        boolean[]   tmp;
        while (h < m  &&  k < n) {
            /* Find the k-th pivot: */
            for (iMax=h; iMax < m  &&  !mat[iMax][k]; iMax++);

            if (iMax == m) {
                /* No pivot in this column, pass to next column */
                k++;
            } else {
                tmp = mat[h];     mat[h] = mat[iMax];     mat[iMax] = tmp;
                if (identMat != null) {
                    tmp = identMat[h];     identMat[h] = identMat[iMax];     identMat[iMax] = tmp;
                }
                /* Do for all rows below pivot: */
                for (int i=h+1; i < m; i++) {
                    /* Do for all remaining elements in current row: */
                    if (mat[i][k]) {
                        for (int j=k; j < nFull; j++) {
                            mat[i][j] ^= mat[h][j];
                        }
                        if (identMat != null) {
                            for (int j = 0; j < identMat.length; j++) {
                                identMat[i][j] ^= identMat[h][j];
                            }
                        }
                    }
                }
                /* Increase pivot row and column */
                h++;     k++;
            }
        }

        return  h;
    }

    /**
     * Removes linearly dependent vectors found in {@code m}.
     */
    public static void  removeLinearlyDependentVectors(List<boolean[]> m) {
        int   n = m.size();
        boolean[][] mTransposed = transpose(m.toArray(new boolean[n][]));
        int   rank = gaussianElimination(mTransposed, null);
        if (rank == n)  return;

        int   h = 0,  k = 0,  delta;
        while (h < mTransposed.length  &&  k < n) {
            if (mTransposed[h][k])  {
                h++;     k++;
            }  else  {
                delta = n - m.size();
                m.remove(k - delta);
                k++;
            }
        }
    }

    /**
     * Computes <a href="https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Computation_by_Gaussian_elimination">
     *     the kernel</a> of matrix {@code mat}, i.e. the set of all vectors x such that Mat * x = 0
     * @param m  a matrix over GF(2) whose kernel (aka basis) needs to be found
     * @return  the elements of the returned two dimensional matrix form the basis of {@code mat}
     */
    public static boolean[][]  kernel(boolean[][] m) {
        return  kernelOfTransposed(transpose(m));
    }

    /**
     * Computes <a href="https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Computation_by_Gaussian_elimination">
     *     the kernel</a> of matrix {@code mat}<sup>T</sup>, i.e. the set of all vectors x such that Mat<sup>T</sup> * x = 0
     * @param mTransposed  a matrix over GF(2) the kernel (aka basis) of whose transposed counterpart needs to be found
     * @return  the elements of the returned two dimensional matrix form the basis of {@code mat}
     */
    public static boolean[][]  kernelOfTransposed(boolean[][] mTransposed) {
        int   n = mTransposed[0].length;
        if (mTransposed.length <= n)  throw  new IllegalArgumentException("Not enough free variables");

        // Calculate a basis of N(T)
        // mTransposed [2176x2048],  tmp [2176x(2048+2176)] = [2176x4224]

        // ... and find the reduced row echelon form using Gaussian elimination. Now perform the
        // same operations on an identity matrix of size n*128.

        // Doing it in one go by using only the columns of T transposed during Gaussian elimination
        boolean[][]  tmp = identityMatrix(mTransposed.length);
        int   rank = gaussianElimination(mTransposed, n, tmp);

        return  Arrays.copyOfRange(tmp, rank, tmp.length);
    }

    /**
     * Generates a square identity matrix of dimension {@code n}.
     */
    public static boolean[][]  identityMatrix(int n) {
        boolean[][]   res = new boolean[n][];
        for (int i=0; i < n; i++) {
            res[i] = new boolean[n];
            res[i][i] = true;
        }
        return  res;
    }

    /**
     * @param col  the index of the column to extract.
     * @return  the column vector identified by {@code col}
     */
    public static boolean[]  extractColumn(boolean[][] mat, int col) {
        assert col < mat[0].length;
        int   m = mat.length;
        boolean[]   res = new boolean[mat.length];

        for (int i=0; i < m; i++) {
            res[i] = mat[i][col];
        }
        return res;
    }

    public static boolean  innerProduct(boolean[] m, boolean[] n) {
        assert  m.length == n.length;
        boolean   r = false;
        for (int i=0; i < m.length; i++) {
            r ^= m[i] & n[i];

        }
        return  r;
    }

    public static boolean[]  multiply(boolean[][] m, boolean[] e) {
        assert  m[0].length == e.length;
        boolean[]  res = new boolean[m.length];
        for (int i=0; i < m.length; i++) {
            boolean   r = false;
            for (int k=0; k < m.length; k++) {
                r ^= m[i][k] & e[k];
            }
            res[i] = r;
        }
        return  res;
    }

    public static boolean[]  multiply(boolean[] e, boolean[][] m) {
        assert  e.length == m.length;
        int   n = m[0].length;
        boolean[]  res = new boolean[n];
        for (int i=0; i < n; i++) {
            boolean   r = false;
            for (int k=0; k < m.length; k++) {
                r ^= e[k] & m[k][i];
            }
            res[i] = r;
        }
        return  res;
    }

    public static boolean[][]  multiply(boolean[][] m, boolean[][] m2) {
        assert  m[0].length == m2.length;
        assert  m2[0].length > 0;
        boolean[][]  res = new boolean[m.length][m2[0].length];
        for (int i=0; i < m.length; i++) {
            for (int j=0; j < m2[0].length; j++) {
                boolean   r = false;
                for (int k=0; k < m2.length; k++) {
                    r ^= m[i][k] & m2[k][j];
                }
                res[i][j] = r;
            }
        }
        return  res;
    }

    public static boolean[][]  scale(boolean[][] m, int k) {
        assert  k > 0;
        boolean[][]   res = m,  x = m;
        k--;
        while (k != 0) {
            if (k % 2 != 0)  res = multiply(res, x);
            x = multiply(x, x);
            k >>= 1;
        }
        return  res;
    }


    public static boolean[][]  add(boolean[][] m, boolean[][] m2) {
        assert  m.length == m2.length  &&  m[0].length == m2[0].length;
        boolean[][]  res = new boolean[m.length][m[0].length];
        for (int i=0; i < m.length; i++) {
            for (int j=0; j < m[0].length; j++) {
                res[i][j] = m[i][j] ^ m2[i][j];
            }
        }
        return  res;
    }

    public static void  print(boolean[][] mat) {
        int   n = mat[0].length;
        for (boolean[] booleans : mat) {
            for (int j = 0; j < n; j++) {
                System.out.print((booleans[j] ? 1 : 0) + " ");
            }
            System.out.println();
        }
    }

    public static boolean  equals(boolean[][] mat, boolean[][] mat2) {
        int   i,  m = mat.length;
        if (mat2.length != mat.length  ||  mat2[0].length != mat[0].length)  return  false;
        for (i=0; i < m  &&  Arrays.equals(mat[i], mat2[i]); i++);
        return  i == m;
    }

}
