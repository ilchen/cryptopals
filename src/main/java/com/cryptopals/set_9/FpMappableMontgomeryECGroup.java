package com.cryptopals.set_9;

import com.cryptopals.Set8;
import com.cryptopals.set_8.MontgomeryECGroup;

import java.math.BigInteger;

import java.util.function.UnaryOperator;

import static java.math.BigInteger.*;

/**
 * Represents a cyclic elliptic curve E(F<sub>p</sub>) group in the Montgomery form whose points allow for
 * an injective map from the elements of the F<sub>p</sub> field. Such Montgomery curves
 * have the following form v<sup>2</sup> = u<sup>3</sup> + A·u<sup>2</sup> + u
 */
public class FpMappableMontgomeryECGroup extends MontgomeryECGroup {
    public static final BigInteger   TWO = valueOf(2),  THREE = valueOf(3),
                                     FIVE = valueOf(5),  EIGHT = valueOf(8);
    private static final long serialVersionUID = -8108634203005429831L;
    private final UnaryOperator<BigInteger>   squareRoot;
    private final BigInteger                  smallNonSquare;

    public FpMappableMontgomeryECGroup(BigInteger p, BigInteger a, BigInteger q, BigInteger cq) {
        super(p, a, BigInteger.ONE, q, cq);
        if (a.equals(BigInteger.ZERO)) {
            throw  new IllegalArgumentException("Illegal curve parameter");
        }
        squareRoot = x -> Set8.squareRoot(x, p); // Using the principal square root where it's defined
        if (p.mod(FOUR).equals(THREE)) {
            smallNonSquare = p.subtract(ONE);
        } else {
            if (p.mod(EIGHT).equals(FIVE)) {
                smallNonSquare = TWO;
            } else {
                BigInteger tmp = ONE;
                while (Set8.legendreSymbol(tmp, p).equals(ONE)) tmp = tmp.add(ONE);
                smallNonSquare = tmp;
            }
        }
    }

    /**
     * Maps an element of F<sub>p</sub> to an element of this curve
     * @param r  an element of F<sub>p</sub> that needs to be mapped, must belong to set { 0, 1, ..., (p-1)/2 }
     * @return  an element of this curve's group if {@code r} can be mapped, or this curve's point at infinity otherwise
     */
    public ECGroupElement  mapFromFp(BigInteger r) {
        if (r.compareTo(getModulus().shiftRight(1)) > 0)  {
            throw  new IllegalArgumentException(String.format("%d is not in the range [0, 1, ..., p/2]", r));
        }
        BigInteger   rSquared = r.multiply(r),  rSquaredTimesNonSquarePlus1 = ONE.add(smallNonSquare.multiply(rSquared));
        // Check if mappable
        if (rSquaredTimesNonSquarePlus1.mod(getModulus()).equals(ZERO)
            ||  getA().multiply(getA()).multiply(smallNonSquare).multiply(rSquared).mod(getModulus()).equals(
                rSquaredTimesNonSquarePlus1.multiply(rSquaredTimesNonSquarePlus1).mod(getModulus())) )  return  O;

        BigInteger   v = getModulus().subtract(getA()).multiply(rSquaredTimesNonSquarePlus1.modInverse(getModulus())),
                     vSquared = v.multiply(v),  vCubed = vSquared.multiply(v),
                     e = Set8.legendreSymbol(vCubed.add(getA().multiply(vSquared)).add(v), getModulus()),
                     x = e.multiply(v).subtract(ONE.subtract(e).multiply(getA()).multiply(TWO.modInverse(getModulus()))),
                     xSquared = x.multiply(x);
        return  createPoint(x, getModulus().subtract(e).multiply(
                                        squareRoot.apply(xSquared.multiply(x).add(getA().multiply(xSquared)).add(x))));
    }

    /**
     * Maps an element of this curve's group to F<sub>p</sub>.
     * @param ecElem  an element of F<sub>p</sub> that needs to be mapped to F<sub>p</sub>
     * @return  an element of F<sub>p</sub> that belongs to set { 0, 1, ..., (p-1)/2 } if {@code ecElem} can be mapped,
     *          {@link Set8#NON_RESIDUE} otherwise
     */
    public BigInteger  mapToFp(com.cryptopals.set_8.ECGroupElement ecElem) {
        // Simple aliases for the sake of readability
        BigInteger   x = ecElem.getX(),  y = ecElem.getY(),  mod = getModulus();
        // Check if mappable
        if (y.equals(ZERO)  &&  !x.equals(ZERO)
                ||  x.equals(getA())
                ||  !Set8.legendreSymbol(mod.subtract(smallNonSquare).multiply(x).multiply(x.add(getA())), mod).equals(ONE))
            return  Set8.NON_RESIDUE;

        return  modulo(Set8.squareRoot(
            y.equals(Set8.squareRoot(y.multiply(y).mod(mod), mod))
                    ?  mod.subtract(x).multiply(x.add(getA()).multiply(smallNonSquare).modInverse(mod))
                    :  mod.subtract(x.add(getA())).multiply(smallNonSquare.multiply(x).modInverse(mod)), mod));
    }

    /**
     * Computes x if x belongs to set { 0, 1, ..., (p-1)/2 }, otherwise -x.
     */
    private BigInteger  modulo(BigInteger x) {
        return  x.compareTo(getModulus().shiftRight(1)) <= 0  ?  x : getModulus().subtract(x);
    }

}
