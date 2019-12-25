package com.cryptopals.set_8;

import lombok.EqualsAndHashCode;

import java.lang.reflect.Array;
import java.util.Arrays;

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
            throw  new IllegalArgumentException("Cannot devide by a zero polynomial");
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
            throw  new IllegalArgumentException("Cannot devide by a zero polynomial");
        PolynomialRing<T>   zero = getZeroPolynomial(),  q = zero,  r = this;
        if (degree() < d.degree()) {
            return  (PolynomialRing<T>[]) new PolynomialRing[] { zero, this } ;
        }
        while (!r.equals(zero)  &&  r.degree() >= d.degree()) {
            @SuppressWarnings("unchecked")
            T coeff = (T) r.coefficients[r.coefficients.length - 1].multiply(d.coefficients[d.coefficients.length - 1].modInverse());
            PolynomialRing<T> c = new PolynomialRing<>(r.degree() - d.degree(), coeff);
            q = q.add(c);
            r = r.subtract(c.multiply(d));
        }
        return  (PolynomialRing<T>[]) new PolynomialRing[] { q, r } ;
    }

    @Override
    public String toString() {
        StringBuilder   sb = new StringBuilder();
        for (int i = coefficients.length - 1; i >= 0 ; i--) {
            T   coeff = coefficients[i];
            if (coeff.equals(coeff.getAdditiveIdentity())  &&  coefficients.length > 1)  continue;
            if (sb.length() > 0)  sb.append(" + ");
            if (!coeff.equals(coeff.getMultiplicativeIdentity()))  sb.append(coefficients[i].toString());
            if (i > 1) {
                sb.append("x^").append(i);
            } else if (i == 1) {
                sb.append("x");
            }
        }
        return  sb.toString();
    }

}
