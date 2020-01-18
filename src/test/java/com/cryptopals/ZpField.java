package com.cryptopals;

import com.cryptopals.set_8.FiniteFieldElement;
import lombok.EqualsAndHashCode;

import java.math.BigInteger;
import java.util.Random;

import static java.math.BigInteger.valueOf;

/**
 * Implements a finite field Zp
 */
public class ZpField {
    private final ZpFieldElement   additiveIdentity,  multiplicativeIdentity;
    private final long   p;
    private final BigInteger   pBI;
    public ZpField(long prime) {
        if (!BigInteger.valueOf(prime).isProbablePrime(100)) {
            throw  new IllegalArgumentException(prime + " is not a prime number");
        }
        p = prime;
        pBI = valueOf(p);
        additiveIdentity = createElement(0);
        multiplicativeIdentity = createElement(1);
    }

    public ZpFieldElement  createElement(long e) {
        return  new ZpFieldElement(e);
    }

    /**
     * Represents elements of the final field Zp
     */
    @EqualsAndHashCode
    public class  ZpFieldElement implements FiniteFieldElement {
        /** Invariant: e is always >= 0 */
        private final long   e;

        /**
         * Constructs an element of finite field Zp out of {@code elem}
         * @param elem  any value, can be negative
         */
        ZpFieldElement(long elem) {
            elem %= p;
            if (elem < 0) {
                elem += p;
            }
            e = elem;
        }

        @Override
        public ZpFieldElement add(FiniteFieldElement that) {
            ZpFieldElement zpFieldElem = (ZpFieldElement) that;
            return  new ZpFieldElement(e + zpFieldElem.e);
        }

        @Override
        public ZpFieldElement subtract(FiniteFieldElement that) {
            ZpFieldElement zpFieldElem = (ZpFieldElement) that;
            return  new ZpFieldElement(e - zpFieldElem.e);
        }

        @Override
        public ZpFieldElement times(BigInteger k) {
            return  new ZpFieldElement(e * k.longValue());
        }

        @Override
        public ZpFieldElement multiply(FiniteFieldElement that) {
            ZpFieldElement zpFieldElem = (ZpFieldElement) that;
            return  new ZpFieldElement(e * zpFieldElem.e);
        }

        @Override
        public ZpFieldElement modInverse() {
            return new ZpFieldElement(valueOf(e).modInverse(pBI).longValue());
        }

        @Override
        public ZpFieldElement scale(BigInteger k) {
            return new ZpFieldElement(valueOf(e).modPow(k, pBI).longValue());
        }

        @Override
        public ZpFieldElement getAdditiveIdentity() {
            return  additiveIdentity;
        }

        @Override
        public ZpFieldElement getMultiplicativeIdentity() {
            return  multiplicativeIdentity;
        }

        @Override
        public ZpFieldElement getRandomElement() {
            return  new ZpFieldElement(new Random().nextInt((int) p));
        }

        @Override
        public BigInteger getOrder() {
            return  valueOf(p);
        }

        @Override
        public BigInteger getCharacteristic() {
            return  getOrder();
        }

        @Override
        public String toString() {
            return Long.toString(e);
        }

        @Override
        public int compareTo(FiniteFieldElement o) {
            ZpFieldElement   that = (ZpFieldElement) o;
            return  Long.compare(e, that.e);
        }
    }
}
