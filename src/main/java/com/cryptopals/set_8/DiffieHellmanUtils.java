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
    public static List<BigInteger> findSmallFactors(BigInteger r) {
        return  findSmallFactors(r, 1 << 16);
    }

    /**
     * Finds all factors of {@code r} that are smaller than {@code upperBound} exclusive and greater than 1 (if any)
     */
    public static List<BigInteger> findSmallFactors(BigInteger r, int upperBound) {
        List<BigInteger>   factors = IntStream.range(2, upperBound) /* Finding all divisors of r */
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

}
