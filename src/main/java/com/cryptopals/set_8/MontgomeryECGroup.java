package com.cryptopals.set_8;

import com.cryptopals.Set8;
import com.squareup.jnagmp.Gmp;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;

import static com.cryptopals.set_8.WeierstrassECGroup.THREE;
import static com.cryptopals.set_8.WeierstrassECGroup.TWO;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

/**
 * Represents an elliptic curve E(F<sub>p</sub>) in the Montgomery form along with points on it. A Montgomery curve
 * has the following form B·v<sup>2</sup> = u<sup>3</sup> + A·u<sup>2</sup> + u
 */
@EqualsAndHashCode
@ToString
public class MontgomeryECGroup implements ECGroup, Serializable {
    protected static final BigInteger   FOUR = BigInteger.valueOf(4);
    @Serial
    private static final long serialVersionUID = 1194952055574519819L;
    @Getter
    private final BigInteger   modulus,  A,  B,  order,  cyclicOrder;
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    public final ECGroupElement O = this.new ECGroupElement(ZERO, ONE);

    public MontgomeryECGroup(BigInteger p, BigInteger a, BigInteger b, BigInteger q) {
        this(p, a, b, q, q);
    }

    /**
     * Constructs a curve that isn't a cyclic group
     * @param q  the order of the group
     * @param cq the order of the largest cyclic subgroup, typically of prime order
     */
    public MontgomeryECGroup(BigInteger p, BigInteger a, BigInteger b, BigInteger q, BigInteger cq) {
        modulus = p;     A = a;     B = b;     order = q;   cyclicOrder = cq;
    }

    public ECGroupElement  getIdentity() {
        return  O;
    }

    /**
     * Calculates the v coordinate of a point on this curve using its u coordinate
     * @param u  a {@code u} coordinate on this curve
     * @return the v coordinate or {@link Set8#NON_RESIDUE} if there's no point on the curve with the given v coordinate
     */
    public BigInteger  mapToY(BigInteger u) {
        BigInteger   uSquare = u.multiply(u),
                vSquared = u.add(A.multiply(uSquare)).add(uSquare.multiply(u)).multiply(B.modInverse(modulus)).mod(modulus);
        return  Set8.squareRoot(vSquared, modulus);
    }

    public boolean  containsPoint(com.cryptopals.set_8.ECGroupElement elem) {
        if (!(elem instanceof ECGroupElement))  return  false;
        BigInteger   vSquare = elem.getY().multiply(elem.getY()).multiply(B).mod(modulus),
                     uSquare = elem.getX().multiply(elem.getX());
        return  vSquare.equals(uSquare.multiply(elem.getX()).add(A.multiply(uSquare)).add(elem.getX()).mod(modulus));
    }

    public ECGroupElement createPoint(BigInteger u, BigInteger v) {
        return  new ECGroupElement(u.mod(modulus), v.mod(modulus));
    }

    public BigInteger ladder(BigInteger u, BigInteger k) {
        BigInteger[]   u2u3 = { ONE, u } ,  w2w3 = { ZERO, ONE };
        for (int i=k.bitLength()-1; i >= 0; i--) {
            BigInteger   b = ONE.and(k.shiftRight(i)),  t,  tt,  ttt;
            cswap(u2u3, b);
            cswap(w2w3, b);
            t = u2u3[0].multiply(u2u3[1]).subtract(w2w3[0].multiply(w2w3[1]));
            tt = u2u3[0].multiply(w2w3[1]).subtract(w2w3[0].multiply(u2u3[1]));
            u2u3[1] = t.multiply(t).mod(modulus);
            w2w3[1] = u.multiply(tt.multiply(tt)).mod(modulus);
            t = u2u3[0].multiply(u2u3[0]);  // u2^2
            tt = w2w3[0].multiply(w2w3[0]); // w2^2
            ttt = u2u3[0].multiply(w2w3[0]);// u2*w2
            u2u3[0] = t.subtract(tt);
            u2u3[0] = u2u3[0].multiply(u2u3[0]).mod(modulus);
            w2w3[0] = FOUR.multiply(ttt).multiply( t.add(A.multiply(ttt)).add(tt) ).mod(modulus);
            cswap(u2u3, b);
            cswap(w2w3, b);
        }
        // return u2u3[0].multiply(w2w3[0].modPow(modulus.subtract(TWO), modulus)).mod(modulus);
        return u2u3[0].multiply(Gmp.modPowInsecure(w2w3[0], modulus.subtract(TWO), modulus)).mod(modulus);
    }

    /**
     * Represents an {@code (u, v)} point on the curve that is an element of E(F<sub>p</sub>).
     * {@code u} and {@code v} are stored {@code mod p}, which ensures their values are always positive.
     */
    @ToString
    final public class ECGroupElement implements com.cryptopals.set_8.ECGroupElement, Serializable {
        @Serial
        private static final long serialVersionUID = 8474348316221211364L;
        final BigInteger   u,  v;

        private ECGroupElement(BigInteger u, BigInteger v) {
            this.u = u;     this.v = v;
        }

        public BigInteger getX() {
            return  u;
        }
        public BigInteger getY() {
            return  v;
        }
        public com.cryptopals.set_8.ECGroupElement  getIdentity() {
            return  O;
        }
        public MontgomeryECGroup  group() {
            return  MontgomeryECGroup.this;
        }

        @Override
        public boolean equals(Object that) {
            if (that == this)  return  true;
            if (!(that instanceof ECGroupElement el))  return  false;
            if (!MontgomeryECGroup.this.equals(el.group()))  return  false;
            return  u.equals(el.u)  &&  v.equals(el.v);
        }

        public int hashCode() {
            int   res = MontgomeryECGroup.this.hashCode();
            res = 31 * res + u.hashCode();
            return  31 * res + v.hashCode();
        }

        public MontgomeryECGroup.ECGroupElement inverse() {
            return  new MontgomeryECGroup.ECGroupElement(u, v.negate().mod(modulus));
        }

        ECGroupElement  timesTwo() {
            if (this.equals(O))  return  this;

            BigInteger   uSquare = u.multiply(u),
                 t = THREE.multiply(uSquare).add(TWO.multiply(A).multiply(u).add(ONE)),
                 tSquared = t.multiply(t),
                 tt = TWO.multiply(B).multiply(v),
                 ttSquared = tt.multiply(tt),
                 u3 = B.multiply(tSquared).multiply(ttSquared.modInverse(modulus)).subtract(A).subtract(u).subtract(u).mod(modulus),
                 v3 = TWO.multiply(u).add(u).add(A).multiply(t).multiply(tt.modInverse(modulus))
                    .subtract(B.multiply(tSquared.multiply(t)).multiply(ttSquared.multiply(tt).modInverse(modulus)))
                    .subtract(v).mod(modulus);
            return  new ECGroupElement(u3, v3);
        }

        public com.cryptopals.set_8.ECGroupElement combine(com.cryptopals.set_8.ECGroupElement that) {
            if (this.equals(O))  return  that;
            if (that.equals(O))  return  this;
            if (this.equals(that.inverse()))  return  O;
            if (this.equals(that))  return  timesTwo();

            BigInteger   deltaX = that.getX().subtract(u),  deltaXSquare = deltaX.multiply(deltaX).mod(modulus),
                         deltaY = that.getY().subtract(v),  deltaYSquare = deltaY.multiply(deltaY).mod(modulus);
            BigInteger   x3 = B.multiply(deltaYSquare).multiply(deltaXSquare.modInverse(modulus)).subtract(A).subtract(u).subtract(that.getX()).mod(modulus);
            BigInteger   y3 = TWO.multiply(u).add(that.getX()).add(A).multiply(deltaY).multiply(deltaX.modInverse(modulus))
                    .subtract(B.multiply(deltaYSquare.multiply(deltaY)).multiply(deltaXSquare.multiply(deltaX).modInverse(modulus)))
                    .subtract(v).mod(modulus);
            return  new ECGroupElement(x3, y3);
        }

        public BigInteger  ladder(BigInteger k) {
            return  MontgomeryECGroup.this.ladder(u, k);
        }

    }

    /**
     * Swaps the elements in the two element array {@code u2u3} in case {@code b.equls(BigInteger.ONE)}.
     * This utility method is required for an efficient implementation of the Montgomery ladder
     */
    private static void  cswap(BigInteger u2u3[], BigInteger b) {
        if (b.equals(ONE)) {
            BigInteger   t = u2u3[0];
            u2u3[0] = u2u3[1];
            u2u3[1] = t;
        }
    }
}
