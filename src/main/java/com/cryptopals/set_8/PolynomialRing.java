package com.cryptopals.set_8;

import com.cryptopals.Set5;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.*;

import static java.math.BigInteger.valueOf;

/**
 * Represents a polynomial ring over {@code T}. This class stores all coefficients of a polynomial using an array.
 * @param <T>  a class representing a finite field
 */
@EqualsAndHashCode
public class PolynomialRing<T extends FiniteFieldElement> {

    /** The element with index {@code i} represents the coefficient of {@code x}<sup>i</sup> */
    private final T[]   coefficients;

    @EqualsAndHashCode.Exclude
    private final T   ZERO,  ONE;

    @SuppressWarnings("unchecked")
    public PolynomialRing(int degree, T lastCoeff) {
        ZERO = (T) lastCoeff.getAdditiveIdentity();
        ONE = (T) lastCoeff.getMultiplicativeIdentity();
        coefficients = (T[]) Array.newInstance(lastCoeff.getClass(), degree + 1);
        coefficients[degree] = lastCoeff;
        while (degree > 0) {
            coefficients[--degree] = ZERO;
        }
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing(T[] coeffs) {
        ZERO = (T) coeffs[0].getAdditiveIdentity();
        ONE = (T) coeffs[0].getMultiplicativeIdentity();
        if (coeffs[coeffs.length-1].equals(ZERO)  &&  coeffs.length > 1) {
            int  idx = coeffs.length - 2;
            for (; idx > 0; idx--) {
                if (!coeffs[idx].equals(ZERO))  {
                    break;
                }
            }
            coefficients = Arrays.copyOf(coeffs, idx + 1);
        } else {
            coefficients = coeffs.clone();
        }
    }

    public int  degree() {
        return  coefficients.length - 1;
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing<T> getZeroPolynomial() {
        return new PolynomialRing<>(0, ZERO);
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing<T> getMultiplicativeIdentity() {
        return new PolynomialRing<>(0, ONE);
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing<T> toMonicPolynomial() {
        if (coefficients[coefficients.length - 1].equals(ONE))  return  this;
        T   newCoeffs[] = coefficients.clone(),  inv = (T) coefficients[coefficients.length - 1].modInverse();
        for (int i=0; i < newCoeffs.length; i++) {
            newCoeffs[i] = (T) newCoeffs[i].multiply(inv);
        }
        return  new PolynomialRing<>(newCoeffs);
    }

    public PolynomialRing<T>  add(PolynomialRing<T> that) {
        T[]   newCoeffs = (coefficients.length >= that.coefficients.length  ?  coefficients : that.coefficients).clone(),
              shortest = coefficients.length >= that.coefficients.length  ?  that.coefficients : coefficients;
        for (int i=0; i < shortest.length; i++) {
            /* All subclasses of FiniteFieldElement return objects of their respective class. */
            @SuppressWarnings("unchecked")
            T  newCoeff = (T) newCoeffs[i].add(shortest[i]);
            newCoeffs[i] = newCoeff;
        }
        return  new PolynomialRing<T>(newCoeffs);
    }

    public PolynomialRing<T>  subtract(PolynomialRing<T> that) {
        T[]   newCoeffs = (coefficients.length >= that.coefficients.length  ?  coefficients : that.coefficients).clone(),
                shortest = coefficients.length >= that.coefficients.length  ?  that.coefficients : coefficients;
        for (int i=0; i < shortest.length; i++) {
            /* All subclasses of FiniteFieldElement return objects of their respective class. */
            @SuppressWarnings("unchecked")
            T  newCoeff = (T) coefficients[i].subtract(that.coefficients[i]);
            newCoeffs[i] = newCoeff;
        }
        int  len = newCoeffs.length;
        @SuppressWarnings("unchecked")
        T  zero = (T) coefficients[0].getAdditiveIdentity();
        while (len > 0  &&  newCoeffs[len - 1].equals(zero))  len--;
        if (len < newCoeffs.length) {
            newCoeffs = Arrays.copyOf(newCoeffs, len > 0  ?  len : 1);
        }
        return  new PolynomialRing<T>(newCoeffs);
    }

    public PolynomialRing<T>  multiply(PolynomialRing<T> that) {
        int   p = coefficients.length,  q = that.coefficients.length;
        T[]   newCoeffs = Arrays.copyOf(coefficients, p + q - 1);
        Arrays.fill(newCoeffs, coefficients[0].getAdditiveIdentity());
        for (int i=0; i < p; i++) {
            for (int j=0; j < q; j++) {
                @SuppressWarnings("unchecked")
                T coeff = (T) coefficients[i].multiply(that.coefficients[j]).add(newCoeffs[i + j]);
                newCoeffs[i + j] = coeff;
            }
        }
        return  new PolynomialRing<>(newCoeffs);
    }

    public PolynomialRing<T>  divide(PolynomialRing<T> d) {
        if (d.degree() == 0  &&  d.coefficients[0].equals(ZERO))
            throw  new IllegalArgumentException("Cannot divide by a zero polynomial");
        if (d.equals(getMultiplicativeIdentity()))  return  this;
        if (degree() < d.degree()) {
            return  getZeroPolynomial();
        }
        @SuppressWarnings("unchecked")
        T   coeff = (T) coefficients[coefficients.length-1].multiply(d.coefficients[d.coefficients.length-1].modInverse());
        PolynomialRing<T>   c = new PolynomialRing<>(degree() - d.degree(), coeff);
        return  c.add(subtract(d.multiply(c)).divide(d));
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing<T>[]  divideAndRemainder(PolynomialRing<T> d) {
        if (d.degree() == 0  &&  d.coefficients[0].equals(ZERO))
            throw  new IllegalArgumentException("Cannot divide by a zero polynomial");
        PolynomialRing<T>   zero = getZeroPolynomial(),  q = zero,  r = this;
        if (degree() < d.degree()) {
            return  (PolynomialRing<T>[]) new PolynomialRing[] { zero, this } ;
        }
        while (!r.equals(zero)  &&  r.degree() >= d.degree()) {
            T coeff = (T) r.coefficients[r.coefficients.length - 1].multiply(d.coefficients[d.coefficients.length - 1].modInverse());
            PolynomialRing<T> c = new PolynomialRing<>(r.degree() - d.degree(), coeff);
            q = q.add(c);
            r = r.subtract(c.multiply(d));
        }
        return  (PolynomialRing<T>[]) new PolynomialRing[] { q, r } ;
    }

    public PolynomialRing<T>  differentiate() {
        if (coefficients.length == 1) {
            return  getZeroPolynomial();
        }
        T[]   newCoeffs = Arrays.copyOfRange(coefficients, 1, coefficients.length);
        for (int i=2; i < coefficients.length; i++) {
            @SuppressWarnings("unchecked")
            T  newCoef = (T) newCoeffs[i-1].times(valueOf(i));
            newCoeffs[i-1] = newCoef;
        }
        return  new PolynomialRing<>(newCoeffs);
    }

    public PolynomialRing<T>  gcd(PolynomialRing<T> h) {
        PolynomialRing<T>   zero = getZeroPolynomial(),  g = this,  r;
        while (!h.equals(zero)) {
            r = g.divideAndRemainder(h)[1];     g = h;     h = r;
        }
        return  g.toMonicPolynomial();
    }

    public PolynomialRing<T>  scale(BigInteger k) {
        PolynomialRing<T> res = getMultiplicativeIdentity(),  x = this;
        while (!k.equals(BigInteger.ZERO)) {
            if (Set5.isOdd(k))  res = res.multiply(x);
            x = x.multiply(x);
            k = k.shiftRight(1);
        }
        return  res;
    }

    @Data
    public static final class PolynomialAndPower<T extends FiniteFieldElement> {
        final PolynomialRing<T>   factor;
        final int  power;
    }

    /**
     * Returns square-free factorization of this polynomial using
     * <a href="https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Square-free_factorization">
     *     the following algorithm</a>
     */
    public List<PolynomialAndPower<T>>  squareFreeFactorization() {
        PolynomialRing<T>  one = getMultiplicativeIdentity(),  c = gcd(differentiate()),  w = divide(c),  y,  fac;
        List<PolynomialAndPower<T>>   res = new ArrayList<>();
        int   i = 1;
        while (!w.equals(one)) {
            y = w.gcd(c);
            fac = w.divide(y);
            if (!fac.equals(one)) {
                res.add(new PolynomialAndPower<>(fac, i));
            }
            i++;     w = y;     c = c.divide(y);
        }

        while (!c.equals(one)) {
            int   characteristic = ZERO.getCharacteristic().intValue(),
                  remainder = c.coefficients.length % characteristic,
                  newLen = c.coefficients.length / characteristic + (remainder != 0  ?  1 : 0);
            T[]   newCoeffs = Arrays.copyOf(c.coefficients, newLen);
            for (i=0; i < c.coefficients.length; i+=characteristic) {
                newCoeffs[i / characteristic] = c.coefficients[i];
            }
            c = new PolynomialRing<>(newCoeffs);
            if (!c.equals(one)) {
                res.add(new PolynomialAndPower<>(c, characteristic));
            }
        }
        return  res;
    }

    /**
     * This polynomial must be square-free for this method to work.
     */
//    public List<PolynomialAndPower<T>>  distinctDegreeFactorizationNaive() {
//        PolynomialRing<T>  fPrime = this,  g,  one = getMultiplicativeIdentity();
//        List<PolynomialAndPower<T>>   res = new ArrayList<>();
//        int   i = 1;
//        while (fPrime.degree() >= i << 1) {
//            Map<BigInteger, T>   map = new LinkedHashMap<>();
//            map.put(BigInteger.ONE, (T) ZERO.subtract(ONE));
//            map.put(ONE.getOrder().pow(i), ONE);
//            g = fPrime.gcd(new PolynomialAsMap<T>(map));
//            if (!g.equals(one)) {
//                res.add(new PolynomialAndPower<>(g, i));
//                fPrime = fPrime.divide(g);
//            }
//            i++;
//        }
//        if (!fPrime.equals(one)) {
//            res.add(new PolynomialAndPower<>(fPrime, fPrime.degree()));
//        }
//
//        if (res.isEmpty()) {
//            res.add(new PolynomialAndPower<>(this, 1));
//        }
//        return  res;
//    }

    @Override
    public String toString() {
        StringBuilder   sb = new StringBuilder();
        for (int i = coefficients.length - 1; i >= 0 ; i--) {
            T   coeff = coefficients[i];
            if (coeff.equals(ZERO)  &&  coefficients.length > 1)  continue;
            if (sb.length() > 0)  sb.append(" + ");
            if (!coeff.equals(ONE)  ||  i == 0)  sb.append(coeff.toString());
            if (i > 1) {
                sb.append("x^").append(i);
            } else if (i == 1) {
                sb.append("x");
            }
        }
        return  sb.toString();
    }

}
