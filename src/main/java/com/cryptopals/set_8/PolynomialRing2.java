package com.cryptopals.set_8;

import com.cryptopals.Set5;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.math.BigInteger;
import java.util.*;
import java.util.function.BinaryOperator;

import static java.math.BigInteger.valueOf;

/**
 * Represents a polynomial ring over {@code T}. This class stores only nonzero coefficients of a polynomial
 * using a {@code Map<BigInteger, T>} whose keys are powers of {@code x} and values are the corresponding coefficients.
 * @param <T>  a class representing a finite field
 */
@EqualsAndHashCode
public final class PolynomialRing2<T extends FiniteFieldElement> {

    /**
     * The element with key {@code i} represents the coefficient of {@code x}<sup>i</sup>. The invariant of this
     * class is such that {@code #coefficientsMap} always contains at least one entry for a key of {@code degree}.
     */
    private final Map<BigInteger, T>   coefficientsMap = new HashMap<>();
    private final BigInteger   degree;

    @EqualsAndHashCode.Exclude
    private final T   ZERO,  ONE;

    public PolynomialRing2(int degree, T lastCoeff) {
        this(valueOf(degree), lastCoeff);
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing2(BigInteger deg, T lastCoeff) {
        coefficientsMap.put(deg, lastCoeff);
        degree = deg;
        ZERO = (T) lastCoeff.getAdditiveIdentity();
        ONE = (T) lastCoeff.getMultiplicativeIdentity();
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing2(T[] coeffs) {
        ZERO = (T) coeffs[0].getAdditiveIdentity();
        ONE = (T) coeffs[0].getMultiplicativeIdentity();
        degree = valueOf(coeffs.length - 1);
        for (int i=0; i < coeffs.length; i++) {
            if (!coeffs[i].equals(ZERO)) {
                coefficientsMap.put(valueOf(i), coeffs[i]);
            }
        }
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing2(Map<BigInteger, T> map) {
        BigInteger   deg = BigInteger.ZERO;
        for (Map.Entry<BigInteger, T> entry : map.entrySet()) {
            if (!entry.getValue().equals(entry.getValue().getAdditiveIdentity())) {
                coefficientsMap.put(entry.getKey(), entry.getValue());
                if (entry.getKey().compareTo(deg) > 0) {
                    deg = entry.getKey();
                }
            }
        }
        degree = deg;
        ZERO = (T) map.values().iterator().next().getAdditiveIdentity();
        ONE = (T) ZERO.getMultiplicativeIdentity();
        if (coefficientsMap.isEmpty()) {
            assert  degree.equals(BigInteger.ZERO);
            coefficientsMap.put(degree, ZERO);
        }

    }

    public T  getLeadingCoefficient() {
        return  coefficientsMap.get(degree);
    }

    public T getCoef(int i) {
        return  getCoef(valueOf(i));
    }
    public T getCoef(BigInteger i) {
        //if (i.compareTo(degree) > 0)  throw  new IllegalArgumentException(i + " is greater than " + degree);
        return  coefficientsMap.getOrDefault(i, ZERO);
    }

    public BigInteger  degree() {
        return  degree;
    }

    public int intDegree() {
        return  degree.intValue();
    }

    public PolynomialRing2<T> getZeroPolynomial() {
        return new PolynomialRing2<>(0, ZERO);
    }

    public PolynomialRing2<T> getMultiplicativeIdentity() {
        return new PolynomialRing2<>(0, ONE);
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing2<T> toMonicPolynomial() {
        T   inv = (T) getLeadingCoefficient().modInverse();
        Map<BigInteger, T>   newMap = new HashMap<>();
        for (Map.Entry<BigInteger, T> entry : coefficientsMap.entrySet()) {
            newMap.put(entry.getKey(), (T) entry.getValue().multiply(inv));

        }
        return  new PolynomialRing2<>(newMap);
    }

    @SuppressWarnings("unchecked")
    private PolynomialRing2<T>  doOp(PolynomialRing2<T> that, BinaryOperator<FiniteFieldElement> op) {
        SortedSet<BigInteger>   keys = new TreeSet<>(coefficientsMap.keySet());
        keys.addAll(that.coefficientsMap.keySet());
        Map<BigInteger, T>   newMap = new HashMap<>();
        for (BigInteger key : keys) {
            newMap.put(key, (T) op.apply(getCoef(key), that.getCoef(key)));
        }
        return  new PolynomialRing2<T>(newMap);
    }

    public PolynomialRing2<T>  add(PolynomialRing2<T> that) {
        return  doOp(that, FiniteFieldElement::add);
    }

    public PolynomialRing2<T>  subtract(PolynomialRing2<T> that) {
        return  doOp(that, FiniteFieldElement::subtract);
    }


    public PolynomialRing2<T>  multiply(PolynomialRing2<T> that) {
        SortedSet<BigInteger>   thisKeys = new TreeSet<>(coefficientsMap.keySet()),
                thatKeys = new TreeSet<>(that.coefficientsMap.keySet());
        Map<BigInteger, T>   newMap = new HashMap<>();

        for (BigInteger thisKey : thisKeys) {
            for (BigInteger thatKey : thatKeys) {
                BigInteger   idx = thisKey.add(thatKey);
                @SuppressWarnings("unchecked")
                T coeff = (T) coefficientsMap.get(thisKey).multiply(that.coefficientsMap.get(thatKey))
                        .add(newMap.getOrDefault(idx, ZERO));
                newMap.put(idx, coeff);
            }
        }
        return  new PolynomialRing2<>(newMap);
    }


    public PolynomialRing2<T>  divide(PolynomialRing2<T> d) {
        if (d.degree.equals(BigInteger.ZERO)  &&  d.getLeadingCoefficient().equals(ZERO))
            throw  new IllegalArgumentException("Cannot divide by a zero polynomial");
        if (d.equals(getMultiplicativeIdentity()))  return  this;
        if (degree.compareTo(d.degree) < 0) {
            return  getZeroPolynomial();
        }
        @SuppressWarnings("unchecked")
        T   coeff = (T) getLeadingCoefficient().multiply(d.getLeadingCoefficient().modInverse());
        PolynomialRing2<T>   c = new PolynomialRing2<>(degree.subtract(d.degree), coeff);
        return  c.add(subtract(d.multiply(c)).divide(d));
    }

    @SuppressWarnings("unchecked")
    public PolynomialRing2<T>[]  divideAndRemainder(PolynomialRing2<T> d) {
        if (d.degree.equals(BigInteger.ZERO)  &&  d.getLeadingCoefficient().equals(ZERO))
            throw  new IllegalArgumentException("Cannot divide by a zero polynomial");
        PolynomialRing2<T>   zero = getZeroPolynomial(),  q = zero,  r = this;
        if (degree.compareTo(d.degree) < 0) {
            return  (PolynomialRing2<T>[]) new PolynomialRing2[] { zero, this } ;
        }
        while (!r.equals(zero)  &&  r.degree.compareTo(d.degree) >= 0) {
            T coeff = (T) r.getLeadingCoefficient().multiply(d.getLeadingCoefficient().modInverse());
            PolynomialRing2<T> c = new PolynomialRing2<>(r.degree.subtract(d.degree), coeff);
            q = q.add(c);
            r = r.subtract(c.multiply(d));
        }
        return  (PolynomialRing2<T>[]) new PolynomialRing2[] { q, r } ;
    }


    public PolynomialRing2<T>  differentiate() {
        if (degree.equals(BigInteger.ZERO)) {
            return  getZeroPolynomial();
        }

        Map<BigInteger, T>   newMap = new HashMap<>();
        for (BigInteger i : coefficientsMap.keySet()) {
            if (i.equals(BigInteger.ZERO))  continue;
            @SuppressWarnings("unchecked")
            T  newCoef = (T) coefficientsMap.get(i).times(i);
            if (!newCoef.equals(ZERO)) {
                newMap.put(i.subtract(BigInteger.ONE), newCoef);
            }
        }
        return  new PolynomialRing2<>(newMap);
    }

    public PolynomialRing2<T>  gcd(PolynomialRing2<T> h) {
        PolynomialRing2<T>   zero = getZeroPolynomial(),  g = this,  r;
        while (!h.equals(zero)) {
            r = g.divideAndRemainder(h)[1];     g = h;     h = r;
        }
        return  g.toMonicPolynomial();
    }


    public PolynomialRing2<T>  scale(BigInteger k) {
        PolynomialRing2<T> res = getMultiplicativeIdentity(),  x = this;
        while (!k.equals(BigInteger.ZERO)) {
            if (Set5.isOdd(k))  res = res.multiply(x);
            x = x.multiply(x);
            k = k.shiftRight(1);
        }
        return  res;
    }

    @Data
    public static final class PolynomialAndPower<T extends FiniteFieldElement> {
        final PolynomialRing2<T>   factor;
        final int  power;
    }

    /**
     * Returns square-free factorization of this polynomial using
     * <a href="https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Square-free_factorization">
     *     the following algorithm</a>
     */
    public List<PolynomialAndPower<T>>  squareFreeFactorization() {
        PolynomialRing2<T>  one = getMultiplicativeIdentity(),  c = gcd(differentiate()),  w = divide(c),  y,  fac;
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
            BigInteger   characteristic = ZERO.getCharacteristic();
            Map<BigInteger, T>   newMap = new HashMap<>();

            for (BigInteger j : c.coefficientsMap.keySet()) {
                if (j.remainder(characteristic).equals(BigInteger.ZERO)) {
                    newMap.put(j.divide(characteristic), c.coefficientsMap.get(j));
                }
            }

            c = new PolynomialRing2<>(newMap);
            if (!c.equals(one)) {
                res.add(new PolynomialAndPower<>(c, characteristic.intValue()));
            }
        }
        return  res;
    }

    /**
     * This polynomial must be square-free for this method to work.
     */
    public List<PolynomialAndPower<T>>  distinctDegreeFactorization() {
        PolynomialRing2<T>  fPrime = this,  g,  one = getMultiplicativeIdentity(),  large;
        List<PolynomialAndPower<T>>   res = new ArrayList<>();
        int   i = 1;
        while (fPrime.degree.compareTo(valueOf(i << 1)) >= 0) {
            large = new PolynomialRing2<>(ONE.getOrder().pow(i), ONE);
            large = large.subtract(new PolynomialRing2<>(1, ONE));

            g = fPrime.gcd(large);
            if (!g.equals(one)) {
                res.add(new PolynomialAndPower<>(g, i));
                fPrime = fPrime.divide(g);
            }
            i++;
        }
        if (!fPrime.equals(one)) {
            res.add(new PolynomialAndPower<>(fPrime, fPrime.intDegree()));
        }

        if (res.isEmpty()) {
            res.add(new PolynomialAndPower<>(this, 1));
        }
        return  res;
    }

    @Override
    public String toString() {
        Comparator<BigInteger>   comparator = BigInteger::compareTo;
        comparator = comparator.reversed();
        SortedSet<BigInteger>   keys = new TreeSet<>(comparator);
        keys.addAll(coefficientsMap.keySet());
        StringBuilder   sb = new StringBuilder();
        for (BigInteger i : keys) {
            T   coeff = coefficientsMap.get(i);
            if (coeff.equals(ZERO)  &&  degree.compareTo(BigInteger.ZERO) > 0)  continue;
            if (sb.length() > 0)  sb.append(" + ");
            if (!coeff.equals(ONE)  ||  i.equals(BigInteger.ZERO))  sb.append(coeff.toString());
            if (i.compareTo(BigInteger.ONE) > 0) {
                sb.append("x^").append(i);
            } else if (i.equals(BigInteger.ONE)) {
                sb.append("x");
            }
        }
        return  sb.toString();
    }

}
