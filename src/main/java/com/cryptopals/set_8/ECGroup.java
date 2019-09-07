package com.cryptopals.set_8;

import com.cryptopals.Set5;
import com.cryptopals.Set8;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;


/**
 * Represents an elliptic curve E(F<sub>p</sub>) in the Weierstrass form along with points on it.
 */
@EqualsAndHashCode
@ToString
final public class ECGroup implements Serializable {
    static private final BigInteger   TWO = BigInteger.valueOf(2),  THREE = BigInteger.valueOf(3);
    @Getter
    private final BigInteger   modulus,  a,  b,  order;
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    public final ECGroupElement O = this.new ECGroupElement(null, null);

    public ECGroup(BigInteger p, BigInteger a, BigInteger b, BigInteger q) {
        modulus = p;     this.a = a;     this.b = b;     order = q;
    }

    /**
     * Calculates the y coordinate of a point on this curve using its y coordinate
     * @param x
     * @return the y coordinate or {@link Set8#NON_RESIDUE} if there's no point on the curve with the given x coordinate
     */
    public BigInteger  mapToY(BigInteger x) {
        BigInteger   ySquared = x.pow(3).add(a.multiply(x)).add(b).mod(modulus);
        return  Set8.squareRoot(ySquared, modulus);
    }

    public boolean  containsPoint(ECGroupElement elem) {
        BigInteger   ySquare = elem.y.multiply(elem.y).mod(modulus),
                     xCube = elem.x.pow(3);
        return  ySquare.equals(xCube.add(a.multiply(elem.x)).add(b).mod(modulus));
    }

    /**
     * Represents an {@code (x, y)} point on the curve that is an element of E(F<sub>p</sub>).
     * {@code x} and {@code y} are stored {@code mod p}, which ensures their values are always positive.
     */
    @ToString
    final public class ECGroupElement implements Serializable {
        final BigInteger   x,  y;

        private ECGroupElement(BigInteger x, BigInteger y) {
            this.x = x;     this.y = y;
        }

        public ECGroup  group() {
            return  ECGroup.this;
        }

        @Override
        public boolean equals(Object that) {
            if (that == this)  return  true;
            if (!(that instanceof ECGroupElement))  return  false;
            ECGroupElement el = (ECGroupElement) that;
            if (!ECGroup.this.equals(el.group()))  return  false;
            return  x.equals(el.x)  &&  y.equals(el.y);
        }

        @Override
        public int hashCode() {
            int   res = ECGroup.this.hashCode();
            res = 31 * res + x.hashCode();
            return  31 * res + y.hashCode();
        }

        public ECGroupElement inverse() {
            return  new ECGroupElement(x, y.negate().mod(modulus));
        }

        public ECGroupElement combine(ECGroupElement that) {
            if (this == O)  return  that;
            if (that == O)  return  this;
            if (this.equals(that.inverse()))  return  O;

            BigInteger   m;
            if (this.equals(that)) {
                m = THREE.multiply(x.multiply(x)).add(a).multiply(TWO.multiply(y).modInverse(modulus)).mod(modulus);
            } else {
                m = that.y.subtract(y).multiply(that.x.subtract(x).modInverse(modulus)).mod(modulus);
            }

            BigInteger  x3 = m.multiply(m).subtract(x).subtract(that.x).mod(modulus);
            return  new ECGroupElement(x3, m.multiply(x.subtract(x3)).subtract(y).mod(modulus));
        }

        public ECGroupElement  scale(BigInteger k) {
            ECGroupElement   res = O,  x = this;
            while (k.compareTo(BigInteger.ZERO) > 0) {
                if (Set5.isOdd(k))  res = res.combine(x);
                x = x.combine(x);
                k = k.shiftRight(1);
            }
            return  res;
        }

        public byte[]  toByteArray() {
            if (this.equals(O)) {
                return  new byte[0];
            } else {
                byte[]   xBytes = x.toByteArray(),  yBytes = y.toByteArray(),  res;
                res = Arrays.copyOf(xBytes, xBytes.length + yBytes.length);
                System.arraycopy(yBytes, 0, res, xBytes.length, yBytes.length);
                return  res;
            }
        }

    }

    public ECGroupElement  createPoint(BigInteger x, BigInteger y) {
        return  new ECGroupElement(x.mod(modulus), y.mod(modulus));
    }
}
