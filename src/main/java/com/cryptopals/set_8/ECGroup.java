package com.cryptopals.set_8;

import com.cryptopals.Set8;

import java.math.BigInteger;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import static com.cryptopals.Set8.NON_RESIDUE;
import static com.cryptopals.set_8.WeierstrassECGroup.TWO;

/**
 * Represents an Elliptic Curve group E(F<sub>p</sub>)
 */
public interface ECGroup {

    /** Returns the order of field F<sub>p</sub> */
    BigInteger  getModulus();

    /** Returns the order of this curve, i.e. the number of points on it. */
    BigInteger  getOrder();

    /** If this group is cyclic, returns its order. Otherwise returns the order of the largest cyclic subgroup. */
    BigInteger  getCyclicOrder();

    /** Returns the identity element of this group */
    ECGroupElement  getIdentity();

    /**
     * Returns the order of the quadratic twist of this curve
     */
    default BigInteger  getTwistOrder() {
        return  getModulus().multiply(TWO).add(TWO).subtract(getOrder());
    }

    /**
     * Calculates the y coordinate of a point on this curve using its x coordinate
     * @return the y coordinate or {@link Set8#NON_RESIDUE} if there's no point on the curve with the given v coordinate
     */
    BigInteger  mapToY(BigInteger x);

    /** Checks if the point {@code elem} is on this curve */
    boolean  containsPoint(ECGroupElement elem);

    /** Creates a point on this curve with designated coordinates */
    ECGroupElement  createPoint(BigInteger x, BigInteger y);

    BigInteger  ladder(BigInteger x, BigInteger k);

    /**
     * Finds a generator of a subgroup of E(GF(p)) of required order
     * @param order  the order the generator must have, it must be a divisor of the order of the curve
     * @param useFullGroup  if {@code true} will search for a generator of the required order withing the whole
     *                      group (the whole group must be cyclic in this case), otherwise will search within
     *                      the largest cyclic subgroup.
     * @return a generator satisfying the order given
     */
    default ECGroupElement  findGenerator(BigInteger order, boolean useFullGroup) {
        BigInteger[]   otherOrder = (useFullGroup  ?  getOrder() : getCyclicOrder()).divideAndRemainder(order);
        if (!otherOrder[1].equals(BigInteger.ZERO))  {
            throw  new IllegalArgumentException(
                    String.format("This curve doesn't contain a subgroup of order %d in its %s",
                            order, useFullGroup  ?  "full group" : "largest cyclic subgroup"));
        }
        Random   rnd = ThreadLocalRandom.current();
        BigInteger     x,  y;
        ECGroupElement   possibleGen = getIdentity();
        do {
            x = new BigInteger(getModulus().bitLength(), rnd);
            y = mapToY(x);
            if (!y.equals(NON_RESIDUE)) {
                possibleGen = createPoint(x, y).scale(otherOrder[0]);
            }
        }  while (possibleGen.equals(getIdentity()));
        return  possibleGen;
    }

    /**
     * Finds a generator of a subgroup of Ē(GF(p)) of required order
     * @param order  the order the generator must have, it must be a divisor of the order of the twist of this curve
     * @return the x coordinate of a generator of the twist curve satisfying the order given
     */
    default BigInteger  findTwistGenerator(BigInteger order) {
        Random   rnd = ThreadLocalRandom.current();
        BigInteger   otherOrder = getTwistOrder().divide(order),  x,  y,  possibleGen = getIdentity().getX();
        do {
            x = new BigInteger(getModulus().bitLength(), rnd);
            y = mapToY(x);
            if (y.equals(NON_RESIDUE)) {  // We are on the twist of this curve
                possibleGen = ladder(x, otherOrder);
            }
        }  while (possibleGen.equals(getIdentity().getX()));
        return   possibleGen;
    }
}
