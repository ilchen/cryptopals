package com.cryptopals.set_8;

import com.cryptopals.Set5;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.math.BigInteger.valueOf;

/**
 * Represents a polynomial ring over {@code T}
 * @param <T>  a class representing a finite field
 */
@EqualsAndHashCode
public class PolynomialRing<T extends FiniteFieldElement> {

    /** The element with index {@code i} represents the coefficient of {@code x}<sup>i</sup> */
    final private T[]   coefficients;

    @SuppressWarnings("unchecked")
    public PolynomialRing(int degree, T lastCoeff) {
        T   zero = (T) lastCoeff.getAdditiveIdentity();
        coefficients = (T[]) Array.newInstance(lastCoeff.getClass(), degree + 1);
        coefficients[degree] = lastCoeff;
        while (degree > 0) {
            coefficients[--degree] = zero;
        }
    }
    public PolynomialRing(T[] coeffs) {
        coefficients = coeffs.clone();
    }

    public int  degree() {
        return  coefficients.length - 1;
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing<T> getZeroPolynomial() {
        return new PolynomialRing<>(0, (T) coefficients[0].getAdditiveIdentity());
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing<T> getMultiplicativeIdentity() {
        return new PolynomialRing<>(0, (T) coefficients[0].getMultiplicativeIdentity());
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing<T> toMonicPolynomial() {
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
        if (d.degree() == 0  &&  d.coefficients[0].equals(d.coefficients[0].getAdditiveIdentity()))
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
        if (d.degree() == 0  &&  d.coefficients[0].equals(d.coefficients[0].getAdditiveIdentity()))
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
            int   characteristic = c.coefficients[0].getCharacteristic().intValue(),
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

    @Override
    public String toString() {
        StringBuilder   sb = new StringBuilder();
        for (int i = coefficients.length - 1; i >= 0 ; i--) {
            T   coeff = coefficients[i];
            if (coeff.equals(coeff.getAdditiveIdentity())  &&  coefficients.length > 1)  continue;
            if (sb.length() > 0)  sb.append(" + ");
            if (!coeff.equals(coeff.getMultiplicativeIdentity())  ||  i == 0)  sb.append(coefficients[i].toString());
            if (i > 1) {
                sb.append("x^").append(i);
            } else if (i == 1) {
                sb.append("x");
            }
        }
        return  sb.toString();
    }

}
