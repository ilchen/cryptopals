package com.cryptopals.set_8;

import lombok.Data;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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

    /**
     * Finds a generator of group Zp* of required order
     * @param p  a prime defining a group Z<sub>p</sub><sup>*</sup>
     * @param order  the order the generator must have
     * @return a generator satisfying the order given
     */
    public static BigInteger  findGenerator(BigInteger p, BigInteger order) {
        Random   rnd = new Random();
        BigInteger   otherOrder = p.subtract(ONE).divide(order),  h;
        do {
            h = new BigInteger(p.bitLength(), rnd).modPow(otherOrder, p);
        }  while (h.equals(ONE));
        return  h;
    }

    public static boolean  isPrimitiveRoot(BigInteger pRoot, BigInteger p, List<BigInteger> smallOrders) {
        for (BigInteger smallOrder : smallOrders) {
            BigInteger otherOrder = p.subtract(ONE).divide(smallOrder);
            if (pRoot.modPow(otherOrder, p).equals(ONE))  return  false;
        }
        return  true;
    }

    /**
     * Finds a smooth prime of the form p = 2<sup>t</sup> + 1
     * @param minExponent  the minimum number of bits the prime found must have
     */
    public static BigInteger  findSmoothPrime(int minExponent) {
        return  IntStream.iterate(minExponent, x -> x+1).mapToObj(x -> ONE.shiftLeft(x).add(ONE))
                .filter(x -> x.isProbablePrime(100)).findFirst().orElse(ZERO);
    }

    @Data
    public static class  PrimeAndFactors {
        final BigInteger   p;
        final List<BigInteger>   factors;
    }

    public static PrimeAndFactors  findSmoothPrime2(int minExponent) {
        Random   rnd = new Random();
        BigInteger   res;
        List<BigInteger>   residues;

        do {
            res = BigInteger.probablePrime(minExponent, rnd);
            residues = DiffieHellmanUtils.findSmallFactors(res.subtract(ONE), 1 << 20);
        }  while (residues.size() < 10);
        return  new PrimeAndFactors(res, residues);
    }

}
