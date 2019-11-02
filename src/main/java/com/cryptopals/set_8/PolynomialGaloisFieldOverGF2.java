package com.cryptopals.set_8;

import com.cryptopals.Set5;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.math.BigInteger;

import static java.math.BigInteger.*;

/**
 * Represents a Polynomial Galois field over GF(2).
 */
@EqualsAndHashCode
public class PolynomialGaloisFieldOverGF2 {
    private final BigInteger   modulus;

    @EqualsAndHashCode.Exclude
    @Getter
    private final FieldElement   additiveIdentity,  multiplicativeIdentity;

    public PolynomialGaloisFieldOverGF2(BigInteger mod) {
        modulus = mod;     additiveIdentity = createElement(ZERO);     multiplicativeIdentity = createElement(ONE);
    }

    /** Returns the order of this field: 2<sup>m</sup> */
    public BigInteger  getOrder() {
        return  ONE.shiftLeft(degree(modulus));
    }

    /** Returns the order of the multiplicative group of this field: 2<sup>m</sup>-1 */
    public BigInteger  getMultiplicativeGroupOrder() {
        return  getOrder().subtract(ONE);
    }

    @Override
    public String toString() {
        return printAsPolynomial(modulus);
    }

    public FieldElement  createElement(BigInteger polynomial) {
        return  new FieldElement(polynomial).mod();
    }

    /**
     * Represents an element of a Polynomial Galois field over GF(2).
     */
    final public class FieldElement {
        private final BigInteger   polynomial;

        public FieldElement(BigInteger poly) {
            polynomial = poly;
        }

        public FieldElement add(FieldElement that) {
            if (!group().equals(that.group()))  throw  new IllegalArgumentException();
            return  new FieldElement(polynomial.xor(that.polynomial));
        }

        public FieldElement  multiply(FieldElement that) {
            BigInteger product = ZERO, a = polynomial, b = that.polynomial;
            while (!a.equals(ZERO)) {
                if (a.and(ONE).equals(ONE)) {
                    product = product.xor(b);
                }
                a = a.shiftRight(1);
                b = b.shiftLeft(1);
                if (degree(b) == degree(modulus)) {
                    b = b.xor(modulus);
                }
            }
            return new FieldElement(product);
        }

        FieldElement  mod() {
            return  new FieldElement(divMod(polynomial, modulus)[1]);
        }

        public FieldElement  modInverse() {
            BigInteger   s2 = ONE,  s1 = ZERO,  s,  t2 = ZERO,  t1 = ONE,  t,  g = polynomial,  h = modulus,  qr[];
            while (!h.equals(ZERO)) {
                qr = divMod(g, h);
                s = s2.xor(mul(qr[0], s1));
                t = t2.xor(mul(qr[0], t1));
                g = h;     h = qr[1];
                s2 = s1;     s1 = s;     t2 = t1;     t1 = t;
            }

            if (!g.equals(ONE))  throw  new IllegalArgumentException("This element cannot be inverted");
            return  new FieldElement(s2);
        }

        public FieldElement  scale(BigInteger k) {
            FieldElement res = multiplicativeIdentity,  x = this;
            while (!k.equals(BigInteger.ZERO)) {
                if (Set5.isOdd(k))  res = res.multiply(x);
                x = x.multiply(x);
                k = k.shiftRight(1);
            }
            return  res;
        }

        public PolynomialGaloisFieldOverGF2  group() {
            return  PolynomialGaloisFieldOverGF2.this;
        }

        @Override
        public boolean equals(Object that) {
            if (that == this)  return  true;
            if (!(that instanceof FieldElement))  return  false;
            FieldElement el = (FieldElement) that;
            if (!PolynomialGaloisFieldOverGF2.this.equals(el.group()))  return  false;
            return  polynomial.equals(el.polynomial);
        }

        @Override
        public int hashCode() {
            int   res = PolynomialGaloisFieldOverGF2.this.hashCode();
            return  31 * res + polynomial.hashCode();
        }

        @Override
        public String toString() {
            return  printAsPolynomial(polynomial) + " / " + group();
        }
    }

    private static int  degree(BigInteger polynomial) {
        return  polynomial.bitLength() - 1;
    }

    private static String  printAsPolynomial(BigInteger polynomial) {
        int   len = polynomial.bitLength();
        if (len == 0)  {
            return  "0";
        }

        StringBuilder   sb = new StringBuilder();
        if (polynomial.and(ONE).equals(ONE)) {
            sb.append("1");
        }
        polynomial = polynomial.shiftRight(1);
        if (len > 1) {
            if (polynomial.and(ONE).equals(ONE)) {
                sb.insert(0, sb.length() > 0  ?  "x + " : "x");
            }
            polynomial = polynomial.shiftRight(1);
        }

        for (int i=2; i < len; i++, polynomial=polynomial.shiftRight(1)) {
            if (polynomial.and(ONE).equals(ONE)) {
                sb.insert(0, sb.length() > 0  ?  String.format("x^%d + ", i) : String.format("x^%d", i));
            }
        }
        return  sb.toString();
    }

    private static BigInteger[]  divMod(BigInteger g, BigInteger h) {
        BigInteger   q = ZERO,  r = g;
        int   d;

        while ((d = degree(r) - degree(h)) >= 0) {
            q = q.xor(ONE.shiftLeft(d));
            r = r.xor(h.shiftLeft(d));
        }

        return  new BigInteger[] { q, r };
    }

    private static BigInteger mul(BigInteger a, BigInteger b) {
        BigInteger product = ZERO;
        while (!a.equals(ZERO)) {
            if (a.and(ONE).equals(ONE)) {
                product = product.xor(b);
            }
            a = a.shiftRight(1);
            b = b.shiftLeft(1);
        }
        return  product;
    }
}
