package com.cryptopals;

import com.cryptopals.set_8.FiniteFieldElement;
import lombok.EqualsAndHashCode;

import java.math.BigInteger;
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
        public FiniteFieldElement add(FiniteFieldElement that) {
            ZpFieldElement zpFieldElem = (ZpFieldElement) that;
            return  new ZpFieldElement(e + zpFieldElem.e);
        }

        @Override
        public FiniteFieldElement subtract(FiniteFieldElement that) {
            ZpFieldElement zpFieldElem = (ZpFieldElement) that;
            return  new ZpFieldElement(e - zpFieldElem.e);
        }

        @Override
        public FiniteFieldElement multiply(FiniteFieldElement that) {
            ZpFieldElement zpFieldElem = (ZpFieldElement) that;
            return  new ZpFieldElement(e * zpFieldElem.e);
        }

        @Override
        public FiniteFieldElement modInverse() {
            return new ZpFieldElement(valueOf(e).modInverse(pBI).longValue());
        }

        @Override
        public FiniteFieldElement scale(BigInteger k) {
            return new ZpFieldElement(valueOf(e).modPow(k, pBI).longValue());
        }

        @Override
        public FiniteFieldElement getAdditiveIdentity() {
            return  additiveIdentity;
        }

        @Override
        public FiniteFieldElement getMultiplicativeIdentity() {
            return  multiplicativeIdentity;
        }

        @Override
        public String toString() {
            return Long.toString(e);
        }
    }
}
