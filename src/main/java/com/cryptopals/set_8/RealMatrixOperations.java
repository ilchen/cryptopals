package com.cryptopals.set_8;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.stream.IntStream;

import static java.math.BigDecimal.*;

/**
 * Implements matrix operations over a field of reals. Where possible unlimited precision arithmetic is used.
 *
 * <br/>
 * Created by Andrei Ilchenko on 19-06-20.
 */
public class RealMatrixOperations {
    private static final BigDecimal HALF = valueOf(.5);

    public static BigDecimal[][]  copy(BigDecimal[][] mat) {
        return  copy(mat, mat[0].length);
    }

    public static BigDecimal[][]  copy(BigDecimal[][] mat, int numColsToCopy) {
        int   m = mat.length,  n = mat[0].length;
        assert  numColsToCopy <= n;
        BigDecimal[][]   res = new BigDecimal[m][n];
        for (int i=0; i < m; i++) {
            System.arraycopy(mat[i], 0, res[i], 0, numColsToCopy);
        }
        return  res;
    }

    public static BigDecimal[][] transposeInPlace(BigDecimal[][] m) {
        for (int i=0; i < m.length; i++) {
            for (int j=i+1; j < m.length; j++) {
                BigDecimal   tmp = m[i][j];
                m[i][j] = m[j][i];
                m[j][i] = tmp;
            }
        }
        return  m;
    }

    public static BigDecimal[]  multiply(BigDecimal[] m, BigDecimal n) {
        BigDecimal[]   r = new BigDecimal[m.length];
        for (int i=0; i < m.length; i++) {
            r[i] = m[i].multiply(n);
        }
        return  r;
    }

    public static BigDecimal[]  add(BigDecimal[] m, BigDecimal[] n) {
        assert  m.length == n.length;
        BigDecimal[]   r = new BigDecimal[m.length];
        for (int i=0; i < m.length; i++) {
            r[i] = m[i].add(n[i]);
        }
        return  r;
    }

    /**
     * @return  {@code m - n}
     */
    public static BigDecimal[]  subtract(BigDecimal[] m, BigDecimal[] n) {
        assert  m.length == n.length;
        BigDecimal[]   r = new BigDecimal[m.length];
        for (int i=0; i < m.length; i++) {
            r[i] = m[i].subtract(n[i]);
        }
        return  r;
    }

    /**
     * Calculates the dot product of vectors {@code m} and {@code n}
     */
    public static BigDecimal  innerProduct(BigDecimal[] m, BigDecimal[] n) {
        assert  m.length == n.length;
        BigDecimal   r = ZERO;
        for (int i=0; i < m.length; i++) {
            r = r.add(m[i].multiply(n[i]));
        }
        return  r;
    }

    public static BigDecimal  mu(BigDecimal[] u, BigDecimal[] v) {
        assert  u.length == v.length;
        BigDecimal   divisor = innerProduct(u, u);
        return  divisor.compareTo(ZERO) == 0  ?  ZERO : innerProduct(v, u).divide(divisor, MathContext.DECIMAL128);
    }

    /**
     * Finds the projection of v onto u. This is basically the part of v going in the same "direction" as u.
     * If u and v are orthogonal, this is the zero vector.
     */
    public static BigDecimal[]  projection(BigDecimal[] u, BigDecimal[] v) {
        assert  u.length == v.length;
        return  multiply(u, mu(u, v));
    }

    /**
     * Converts a basis captured in {@code B} into an equivalent basis of mutually orthogonal vectors.
     */
    public static BigDecimal[][]  gramSchmidt(BigDecimal[][] B) {
        BigDecimal   Q[][] = new BigDecimal[B.length][B.length],  accu[] = new BigDecimal[B.length];
        Arrays.fill(accu, ZERO);

        for (int i=0; i < B.length; i++) {
            final int   finI = i;
            Q[i] = subtract(B[i],
                    IntStream.range(0, i).mapToObj(j -> projection(Q[j], B[finI])).reduce(accu, RealMatrixOperations::add));
        }
        return  Q;
    }

    /**
     * Finds a reduced basis for lattice {@code B} using the Lenstra-Lenstra-Lovasz (LLL) algorithm.
     */
    public static BigDecimal[][]  lLL(BigDecimal[][] B, BigDecimal delta) {
        BigDecimal[][]   res = copy(B),  Q = gramSchmidt(res);

        for (int k=1; k < B.length;) {
            for (int j=k-1; j >=0; j--) {
                if (mu(Q[j], res[k]).abs().compareTo(HALF) > 0) {
                    res[k] = subtract(res[k],
                            multiply(res[j], mu(Q[j], res[k]).add(HALF).setScale(0, RoundingMode.FLOOR)));
                    Q = gramSchmidt(res);
                }
            }

            if (innerProduct(Q[k], Q[k]).compareTo(
                    delta.subtract(mu(Q[k-1], res[k]).pow(2)).multiply(innerProduct(Q[k-1], Q[k-1])) ) >= 0)  k++;
            else {
                BigDecimal[]   tmp = res[k];
                res[k] = res[k-1];     res[k-1] = tmp;
                Q = gramSchmidt(res);
                k = Integer.max(k-1, 1);
            }

        }

        return  res;
    }

    public static boolean  equals(BigDecimal[][] mat, BigDecimal[][] mat2) {
        int   i,  m = mat.length;
        if (mat2.length != mat.length  ||  mat2[0].length != mat[0].length)  return  false;
        for (i=0; i < m  &&  Arrays.equals(mat[i], mat2[i]); i++);
        return  i == m;
    }

    public static void  print(BigDecimal[][] mat) {
        int   n = mat[0].length;
        for (BigDecimal[] row : mat) {
            for (int j = 0; j < n; j++) {
                System.out.printf("%.3f ", row[j]);
            }
            System.out.println();
        }
    }
}
