package com.cryptopals.set_8;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Implements  matrix operations over GF(2).
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

    public static int  gaussianElimination(boolean[][] mat) {
        return  gaussianElimination(mat, mat[0].length);
    }

    /**
     * Computes a row echelon form of {@code mat} by Gaussian elimination. The algorithm is an adaptation
     * of <a href="https://en.wikipedia.org/wiki/Gaussian_elimination#Pseudocode">this algorithm</a> for GF(2).
     * A similar algorithm albeit with a small omission can be found in
     * <a href="http://www.hyperelliptic.org/tanja/SHARCS/talks06/smith_revised.pdf">this paper</a>.
     *
     * @param mat  a matrix that will modified in place
     * @param n  the number of columns to use when applying Gaussian elimination
     * @return  the rank of the first {@code n} columns
     */
    public static int  gaussianElimination(boolean[][] mat, int n) {
        assert  n <= mat[0].length;
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
                /* Do for all rows below pivot: */
                for (int i=h+1; i < m; i++) {
                    /* Do for all remaining elements in current row: */
                    if (/*i != h  &&  */mat[i][k]) {
                        for (int j=k; j < nFull; j++) {
                            mat[i][j] ^= mat[h][j];
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
     * Computes <a href="https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Computation_by_Gaussian_elimination">
     *     the kernel</a> of matrix {@code mat}, i.e. the set of all vectors x such that Mat * x = 0
     * @param m
     * @return  the elements of the returned two dimensional matrix form the basis of {@code mat}
     */
    public static boolean[][]  kernel(boolean[][] m) {
        if (m.length >= m[0].length)  throw  new IllegalArgumentException("Not enough free variables");

        // Calculate a basis of N(T)
        // mTransposed [2176x2048],  tmp [2176x(2048+2176)] = [2176x4224]
        // What you want to do is transpose T (i.e. flip it across its diagonal)
        boolean[][]  mTransposed = transpose(m);

        // ... and find the reduced row echelon form using Gaussian elimination. Now perform the
        // same operations on an identity matrix of size n*128.

        // Doing it in one go by using only the columns of T transposed during Gaussian elimination
        boolean[][]  tmp = appendIdentityMatrix(mTransposed);
        gaussianElimination(tmp, m.length);
        tmp = extractBasisMatrix(tmp);

        return  tmp;
    }

    /**
     * Computes a column echelon form of {@code mat} by Gaussian elimination. The algorithm is taken from
     * of <a href="https://www.cs.umd.edu/%7Egasarch/TOPICS/factoring/fastgauss.pdf">this paper</a>.
     * @param mat
     */
    public static void gaussianEliminationColumnEchelonForm(boolean[][] mat) {
        int   m = mat.length,  n = mat[0].length,  iMax;
        for (int j=0; j < n; j++) {
            iMax = -1;
            for (int i=0; i < m; i++)  {
                if (mat[i][j])  {
                    iMax = i;
                    break;
                }
            }
            if (iMax >= 0) {
                for (int k=0; k < n; k++) {
                    if (k == j)  continue;
                    if (mat[iMax][k]) {
                        for (int i=0; i < m; i++) {
                            mat[i][k] ^= mat[i][j];
                        }
                    }
                }
            }
        }
    }

    /**
     * Appends the columns of an identity matrix to the right of the columns of {@code mat}
     * @return  {@code mat} concatenated with an identity matrix.
     */
    public static boolean[][]  appendIdentityMatrix(boolean[][] mat) {
        int   m = mat.length,  n = mat[0].length;
        boolean[][]   res = new boolean[m][m + n];

        for (int i=0; i < m; i++) {
            System.arraycopy(mat[i], 0, res[i], 0, n);
            res[i][i+n] = true;
        }
        return res;
    }

    /**
     * Appends the columns of an identity matrix to the bottom of {@code mat}
     * @return  {@code mat} concatenated with an identity matrix.
     */
    public static boolean[][]  appendIdentityMatrixBottom(boolean[][] mat) {
        int   m = mat.length,  n = mat[0].length;
        boolean[][]   res = new boolean[m+n][n];

        for (int i=0; i < m; i++) {
            System.arraycopy(mat[i], 0, res[i], 0, n);
        }
        for (int i=0; i < n; i++) {
            res[i+m][i] = true;
        }
        return res;
    }

    /**
     * Extracts the rows that correspond to the zero rows in the reduced row echelon form of T
     * transpose. They form a basis for N(T).
     */
    public static boolean[][]  extractBasisMatrix(boolean[][] mat) {
        int   m = mat.length,  n = mat[0].length - m,  i,  j;
        boolean[]  row;

        NEXT_ROW:
        for (i=0; i < m; i++) {
            for (j = 0; j < n; j++) {
                if (mat[i][j]) continue NEXT_ROW;
            }
            // Since the matrix is in a row echelon form, all the rows below will also have zeros as their first n elements
            break  NEXT_ROW;
        }
        boolean[][]   res = new boolean[m-i][];
        for (j=i; j < m; j++)  res[j-i] = Arrays.copyOfRange(mat[j], n, n + m);
        return  res;
    }

    /**
     * Extracts a basis from {@code mat}.
     * @param mat  represents a GF(2) matrix in a column echelon form computed in accordance with
     *             <a href="https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Computation_by_Gaussian_elimination">
     *             this algorithm</a>
     * @return
     */
    public static boolean[][]  extractBasisMatrixBottom(boolean[][] mat) {
        int   m = mat.length,  n = mat[0].length,  bm = m - n;
        assert  m > n;
        List<boolean[]>   res = new ArrayList<>();

        NEXT_ROW:
        for (int j=0; j < n; j++) {
            // Check whether the jth column of B is a zero column
            for (int i=0; i < bm; i++) {
                if (mat[i][j])  continue  NEXT_ROW;
            }

            // Copy the jth column of C if it is not a zero column
            boolean   col[] = new boolean[n],  retain = false;
            for (int i=bm; i < m; i++) {
                if (mat[i][j])  retain = true;
                col[i-bm] = mat[i][j];
            }
            if (retain) {
                res.add(col);
            }
        }

        boolean[][]  ret = new boolean[res.size()][];

        return  res.toArray(ret);
    }

    public static boolean[][]  appendZeroColumn(boolean[][] mat) {
        int   m = mat.length,  n = mat[0].length;
        boolean[][]   res = new boolean[m][n + 1];
        for (int i=0; i < m; i++) {
            System.arraycopy(mat[i], 0, res[i], 0, n);
        }
        return  res;
    }

    /**
     * @param col  the index of the column to extract.
     * @return
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
        int   m = mat.length,  n = mat[0].length;
        for (boolean[] booleans : mat) {
            for (int j = 0; j < n; j++) {
                System.out.print((booleans[j] ? 1 : 0) + " ");
            }
            System.out.println();
        }
    }

    public static boolean  equals(boolean[][] mat, boolean[][] mat2) {
        int   i,  m = mat.length,  n = mat[0].length;
        if (mat2.length != mat.length  ||  mat2[0].length != mat[0].length)  return  false;
        for (i=0; i < m  &&  Arrays.equals(mat[i], mat2[i]); i++);
        return  i == m;
    }

}
