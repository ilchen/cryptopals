package com.cryptopals.set_8;

import com.cryptopals.Set8;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

import static java.math.BigInteger.*;


/**
 * Represents an elliptic curve E(F<sub>p</sub>) in the Weierstrass form along with points on it. The class contains
 * a deliberate security bug &mdash; group operations on the points of this curve will trigger {@link IllegalStateException}s
 * with a specified incidence rate.
 */
@EqualsAndHashCode
@ToString
final public class FaultyWeierstrassECGroup implements ECGroup, Serializable {
    private static final long serialVersionUID = 349435680439580034L;
    private static final Random   rnd = new Random();
    static final BigInteger   TWO = BigInteger.valueOf(2),  THREE = BigInteger.valueOf(3);
    @Getter
    private final BigInteger   modulus,  a,  b,  order,  cyclicOrder;
    private final BigInteger   faultIncidence;
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    public final ECGroupElement O = this.new ECGroupElement(null, null);

    public FaultyWeierstrassECGroup(BigInteger p, BigInteger a, BigInteger b, BigInteger q, BigInteger incidence) {
        this(p, a, b, q, q, incidence);
    }

    /**
     * Constructs a curve that isn't a cyclic group
     * @param q  the order of the group
     * @param cq the order of the largest cyclic subgroup
     * @param incidence  fault incidence: faults will occur one out of {@code incidence} times
     */
    public FaultyWeierstrassECGroup(BigInteger p, BigInteger a, BigInteger b, BigInteger q, BigInteger cq,
                                    BigInteger incidence) {
        modulus = p;     this.a = a;     this.b = b;     order = q;     cyclicOrder = cq;     faultIncidence = incidence;
    }

    public ECGroupElement getIdentity() {
        return  O;
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

    public boolean  containsPoint(com.cryptopals.set_8.ECGroupElement elem) {
        if (!(elem instanceof ECGroupElement))  return  false;
        BigInteger   ySquare = elem.getY().multiply(elem.getY()).mod(modulus),
                xCube = elem.getX().pow(3);
        return  ySquare.equals(xCube.add(a.multiply(elem.getX())).add(b).mod(modulus));
    }

    public ECGroupElement  createPoint(BigInteger x, BigInteger y) {
        return  new ECGroupElement(x.mod(modulus), y.mod(modulus));
    }

    public ECGroupElement  createRandomPoint() {
        BigInteger   x,  y;
        do {
            x = new BigInteger(modulus.bitLength(), rnd).mod(modulus);
            y = mapToY(x);
        }  while (Set8.NON_RESIDUE.equals(y));
        return  new ECGroupElement(x, y);
    }

    public BigInteger  ladder(BigInteger x, BigInteger k) {
        throw  new UnsupportedOperationException();
    }

    /**
     * Represents an {@code (x, y)} point on the curve that is an element of E(F<sub>p</sub>).
     * {@code x} and {@code y} are stored {@code mod p}, which ensures their values are always positive.
     */
    @ToString
    final public class ECGroupElement implements com.cryptopals.set_8.ECGroupElement, Serializable {
        private static final long serialVersionUID = -118582543424541427L;
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
        public FaultyWeierstrassECGroup group() {
            return  FaultyWeierstrassECGroup.this;
        }

        public BigInteger ladder(BigInteger k) {
            return  FaultyWeierstrassECGroup.this.ladder(x, k);
        }

        @Override
        public boolean equals(Object that) {
            if (that == this)  return  true;
            if (!(that instanceof ECGroupElement))  return  false;
            ECGroupElement el = (ECGroupElement) that;
            if (!FaultyWeierstrassECGroup.this.equals(el.group()))  return  false;
            return  x.equals(el.x)  &&  y.equals(el.y);
        }

        @Override
        public int hashCode() {
            int   res = FaultyWeierstrassECGroup.this.hashCode();
            res = 31 * res + x.hashCode();
            return  31 * res + y.hashCode();
        }

        @Override
        public com.cryptopals.set_8.ECGroupElement scale(BigInteger k) {
            int   n = k.bitLength();
            com.cryptopals.set_8.ECGroupElement res = this;
            for (int i=n-2; i >= 0; i--) {
                res = res.combine(res);
                if (k.testBit(i))  {
                    res = res.combine(this);
                }
            }
            return  res;
        }

        public ECGroupElement inverse() {
            return  new ECGroupElement(x, y.negate().mod(modulus));
        }

        /**
         * A deliberately flawed version of combine that triggers a {@link IllegalStateException} upon the following
         * condition {@code (this.x * that.x) % incidence == 0}. For the rest it behaves correctly.
         */
        public com.cryptopals.set_8.ECGroupElement combine(com.cryptopals.set_8.ECGroupElement that) {
            if (this.equals(O))  return  that;
            if (that.equals(O))  return  this;

            if (x.multiply(that.getX()).mod(faultIncidence).equals(ZERO)) {
                throw  new IllegalStateException();
            }
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
