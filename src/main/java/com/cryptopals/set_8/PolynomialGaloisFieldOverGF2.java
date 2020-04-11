package com.cryptopals.set_8;

import com.cryptopals.Set5;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static java.math.BigInteger.*;

/**
 * Represents a Polynomial Galois field over GF(2) aka GF(2<sup>128</sup>).
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
     * @param polynomial  the i<sup>th</sup> element of the array is the coefficient of x<sup>i</sup>, and so on.
     */
    public FieldElement  createElement(boolean[] polynomial) {
        BigInteger   res = ZERO;
        for (int i=0; i < polynomial.length; i++) {
            if (polynomial[i]) {
                res = res.setBit(i);
            }
        }
        return  new FieldElement(res).mod();
    }

    public FieldElement  createRandomElement() {
        return  new FieldElement(new BigInteger(modulus.bitLength(), new Random())).mod();
    }

    /**
     * Returns a matrix that can be used to implement squaring operations on the elements of this field represented
     * in a vector form.
     * <br/>
     * Squaring in GF(2<sup>128</sup>) is linear. This is because (a + b)<sup>2</sup> = a<sup>2</sup> + b<sup>2</sup> in
     * GF(2<sup>128</sup>).
     */
    public boolean[][]  getSquaringMatrix() {
        int   n = degree(modulus);
        boolean[][]  ms = new boolean[n][];
        for (int i=0; i < n; i++) {
            FieldElement   x2ith = createElement(ONE.shiftLeft(i));
            ms[i] = x2ith.multiply(x2ith).asVector();
        }
        BooleanMatrixOperations.transposeInPlace(ms);
        return  ms;
    }


    /**
     * Represents an element of a Polynomial Galois field over GF(2).
     */
    final public class FieldElement implements FiniteFieldElement {
        private final BigInteger   polynomial;

        FieldElement(BigInteger poly) {
            polynomial = poly;
        }

        public FieldElement getAdditiveIdentity() {
            return additiveIdentity;
        }

        public FieldElement getMultiplicativeIdentity() {
            return multiplicativeIdentity;
        }

        /** Returns a uniformly distributed element of this polynomial field */
        public FieldElement getRandomElement() {
            return  createRandomElement();
        }

        public BigInteger  getOrder() {
            return  PolynomialGaloisFieldOverGF2.this.getOrder();
        }

        @Override
        public BigInteger getCharacteristic() {
            return  valueOf(2);
        }

        public FieldElement add(FiniteFieldElement t) {
            FieldElement  that = (FieldElement) t;
            if (!group().equals(that.group()))  throw  new IllegalArgumentException();
            return  new FieldElement(polynomial.xor(that.polynomial));
        }

        public FieldElement subtract(FiniteFieldElement t) {
            return  add(t);
        }

        public FieldElement times(BigInteger k) {
            FieldElement res = additiveIdentity,  x = this;
            while (!k.equals(BigInteger.ZERO)) {
                if (Set5.isOdd(k))  res = res.add(x);
                x = x.add(x);
                k = k.shiftRight(1);
            }
            return  res;
        }

        /** Converts to a byte array in such a way that the leftmost bit is the coefficient of x^0, and so on. */
        byte[]  asArray() {
            int   byteSize = degree(modulus) >> 3;
            byte[]   res = polynomial.toByteArray();
            assert  res.length > byteSize  ||  (res[0] & 0x80) == 0;
            if (res.length > byteSize) {
                res = Arrays.copyOfRange(res, 1, byteSize + 1);
            }  else if (res.length < byteSize) {
                byte[]   r = new byte[byteSize];
                System.arraycopy(res, 0, r, byteSize - res.length, res.length);
                res = r;
            }
            return  GCM.reverseBits(res);
        }

        /** Converts to a boolean array in such a way that the i<sup>th</sup> element of the array is the coefficient
         * of x<sup>i</sup>, and so on. */
        public boolean[]  asVector() {
            boolean[]   res = new boolean[degree(modulus)];
            for (int i=0; i < res.length; i++) {
                res[i] = polynomial.testBit(i);
            }
            return  res;
        }

        /**
         * Converts this element to a matrix representation.
         * @return  a [128x128] boolean matrix that can be used for multiplication by a constant.
         */
        public boolean[][]  asMatrix() {
            int   n = degree(modulus);
            boolean[][]   mc = new boolean[n][];
            for (int i=0; i < n; i++) {
                PolynomialGaloisFieldOverGF2.FieldElement   x2ith = createElement(ONE.shiftLeft(i));
                mc[i] = multiply(x2ith).asVector();
            }
            BooleanMatrixOperations.transposeInPlace(mc);
            return  mc;
        }

        /**
         * Returns the coefficient of x<sup>pow</sup>.
         */
        public boolean  getCoefficient(int pow) {
            return  polynomial.testBit(pow);
        }

        public FieldElement  multiply(FiniteFieldElement t) {
            FieldElement  that = (FieldElement) t;
            assert  polynomial.signum() >= 0;
            assert  that.polynomial.signum() >= 0;
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
            return  polynomial.toString(16);
        }

        public String toPolynomialString() {
            return  printAsPolynomial(polynomial) + " / " + group();
        }

        @Override
        public int compareTo(FiniteFieldElement o) {
            FieldElement   that = (FieldElement) o;
            return polynomial.compareTo(that.polynomial);
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
