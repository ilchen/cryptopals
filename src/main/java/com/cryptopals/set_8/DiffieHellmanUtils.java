package com.cryptopals.set_8;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.cryptopals.Set8.NON_RESIDUE;
import static java.math.BigInteger.*;

final public class DiffieHellmanUtils {

    /**
     * Finds all factors of {@code r} that are smaller than 2^16 and greater than 1 (if any)
     */
    static public List<BigInteger> findSmallFactors(BigInteger r) {
        List<BigInteger>   factors = IntStream.range(2, 1 << 16) /* Finding all divisors of r */
                .filter(i -> r.remainder(BigInteger.valueOf(i)).equals(ZERO))
                .boxed().map(BigInteger::valueOf).collect(Collectors.toCollection(ArrayList::new));

        for (int i=0; i < factors.size() - 1; i++) {       /* Getting rid of non-prime divisors */
            BigInteger   f = factors.get(i);
            for (int j=i+1; j < factors.size();) {
                if (factors.get(j).remainder(f).equals(ZERO)) {
                    factors.remove(j);
                } else  j++;
            }
        }

        return  factors;
    }

    /**
     * Finds a generator of a subgroup of E(GF(p)) of required order
     * @param order  the order the generator must have, it must be a divisor of the order of the curve
     * @return a generator satisfying the order given
     */
    static public ECGroup.ECGroupElement  findGenerator(ECGroup curve, BigInteger order) {
        Random rnd = new Random();
        BigInteger   otherOrder = curve.getOrder().divide(order),  x,  y;
        ECGroup.ECGroupElement   possibleGen = curve.O;
        do {
            x = new BigInteger(curve.getModulus().bitLength(), rnd);
            y = curve.mapToY(x);
            if (!y.equals(NON_RESIDUE)) {
                possibleGen = curve.createPoint(x, y).scale(otherOrder);
            }
        }  while (possibleGen == curve.O  ||  possibleGen.equals(curve.O));
        return  possibleGen;
    }
}
