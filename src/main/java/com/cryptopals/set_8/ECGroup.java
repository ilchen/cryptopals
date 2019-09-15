package com.cryptopals.set_8;

import com.cryptopals.Set8;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;
import java.math.BigInteger;

import static java.math.BigInteger.ZERO;


/**
 * Represents an elliptic curve E(F<sub>p</sub>) in the Weierstrass form along with points on it.
 */
@EqualsAndHashCode
@ToString
final public class ECGroup implements Serializable {
    private static final long serialVersionUID = -2465568918540999150L;
    static final BigInteger   TWO = BigInteger.valueOf(2),  THREE = BigInteger.valueOf(3);
    @Getter
    private final BigInteger   modulus,  a,  b,  order;
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    public final ECGroupElement O = this.new ECGroupElement(null, null);

    public ECGroup(BigInteger p, BigInteger a, BigInteger b, BigInteger q) {
        modulus = p;     this.a = a;     this.b = b;     order = q;
    }

    /**
     * Calculates the y coordinate of a point on this curve using its x coordinate
     * @param x
     * @return the y coordinate or {@link Set8#NON_RESIDUE} if there's no point on the curve with the given x coordinate
     */
    public BigInteger  mapToY(BigInteger x) {
        BigInteger   ySquared = x.pow(3).add(a.multiply(x)).add(b).mod(modulus);
        return  ySquared.equals(ZERO)  ?  ZERO : Set8.squareRoot(ySquared, modulus);
    }

    public boolean  containsPoint(ECGroupElement elem) {
        BigInteger   ySquare = elem.y.multiply(elem.y).mod(modulus),
                     xCube = elem.x.pow(3);
        return  ySquare.equals(xCube.add(a.multiply(elem.x)).add(b).mod(modulus));
    }

    public ECGroupElement  createPoint(BigInteger x, BigInteger y) {
        return  new ECGroupElement(x.mod(modulus), y.mod(modulus));
    }

    /**
     * Represents an {@code (x, y)} point on the curve that is an element of E(F<sub>p</sub>).
     * {@code x} and {@code y} are stored {@code mod p}, which ensures their values are always positive.
     */
    @ToString
    final public class ECGroupElement implements com.cryptopals.set_8.ECGroupElement, Serializable {
        private static final long serialVersionUID = 8474348316221211363L;
        final BigInteger   x,  y;

        private ECGroupElement(BigInteger x, BigInteger y) {
            this.x = x;     this.y = y;
        }

        public BigInteger getX() {
            return  x;
        }
        public BigInteger getY() {
            return  y;
        }
        public com.cryptopals.set_8.ECGroupElement  getIdentity() {
            return  O;
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

        public com.cryptopals.set_8.ECGroupElement combine(com.cryptopals.set_8.ECGroupElement that) {
            if (this.equals(O))  return  that;
            if (that.equals(O))  return  this;
            if (this.equals(that.inverse()))  return  O;

            BigInteger   m;
            if (this.equals(that)) {
                m = THREE.multiply(x.multiply(x)).add(a).multiply(TWO.multiply(y).modInverse(modulus)).mod(modulus);
            } else {
                m = that.getY().subtract(y).multiply(that.getX().subtract(x).modInverse(modulus)).mod(modulus);
            }

            BigInteger  x3 = m.multiply(m).subtract(x).subtract(that.getX()).mod(modulus);
            return  new ECGroupElement(x3, m.multiply(x.subtract(x3)).subtract(y).mod(modulus));
        }

    }

}
