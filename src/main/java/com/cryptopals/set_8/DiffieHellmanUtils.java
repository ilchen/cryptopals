package com.cryptopals.set_8;

import com.squareup.jnagmp.Gmp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static java.math.BigInteger.*;

final public class DiffieHellmanUtils {
    static final BigInteger   TWO = valueOf(2);

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
        List<BigInteger>   factors = new ArrayList<>();
        BigInteger   tmp;
        if (r.remainder(TWO).equals(ZERO))  factors.add(TWO);
        for (int i=3; i < upperBound; i+=2) {  /* Finding all divisors of r */
            tmp = valueOf(i);
            if (r.remainder(tmp).equals(ZERO))  factors.add(tmp);
        }
//        List<BigInteger>   factors = IntStream.range(2, upperBound) /* Finding all divisors of r */
//                .filter(i -> r.remainder(BigInteger.valueOf(i)).equals(ZERO))
//                .boxed().map(BigInteger::valueOf).collect(Collectors.toCollection(ArrayList::new));
//        return  LongStream.range(2, upperBound).parallel().mapToObj(BigInteger::valueOf)
//                .filter(i -> i.isProbablePrime(64)  &&  r.remainder(i).equals(ZERO))
//                .collect(Collectors.toList());

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
     * Finds all factors of {@code r} that are in {@code smallPrimes}
     */
    private static List<BigInteger> findSmallFactors(BigInteger r, int smallPrimes[]) {
        List<BigInteger>   factors = new ArrayList<>();
        BigInteger   tmp;

        for (int i : smallPrimes) {
            tmp = valueOf(i);
            if (r.remainder(tmp).equals(ZERO))  factors.add(tmp);
        }

        return  factors;
    }

    public static int[]  findSmallPrimes(int upperBound) {
        List<Integer>   res = new ArrayList<>();
        res.add(2);
        for (int i=3; i < upperBound; i+=2) {
            int  j = 0,  n = res.size();
            for (; j < n; j++) {
                if (i % res.get(j) == 0)  break;
            }
            if (j == n)  res.add(i);
        }
        return  res.stream().mapToInt(x -> x).toArray();
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
            // h = new BigInteger(p.bitLength(), rnd).modPow(otherOrder, p);
            h = Gmp.modPowInsecure(new BigInteger(p.bitLength(), rnd), otherOrder, p);
        }  while (h.equals(ONE));
        return  h;
    }

    public static boolean  isPrimitiveRoot(BigInteger pRoot, BigInteger p, List<BigInteger> smallOrders) {
        for (BigInteger smallOrder : smallOrders) {
            BigInteger otherOrder = p.subtract(ONE).divide(smallOrder);
            // if (pRoot.modPow(otherOrder, p).equals(ONE))  return  false;
            if (Gmp.modPowInsecure(pRoot, otherOrder, p).equals(ONE))  return  false;
        }
        return  true;
    }

    public static record  PrimeAndFactors(BigInteger p, List<BigInteger> factors) {  }

    /**
     * Finds a prime {@code p} whose Zp* group contains at least 10 subgroups
     * @param minExponent  the minimum number of bits the returned prime must have
     * @param smallPrimes  small primes starting from 2, for good results should contain all primes
     *                     starting up till at least 2^20
     */
    public static PrimeAndFactors findSmoothPrime(int minExponent, int smallPrimes[]) {
        Random   rnd = new Random();
        BigInteger   res;
        List<BigInteger>   residues;

        do {
            res = BigInteger.probablePrime(minExponent, rnd);
            residues = DiffieHellmanUtils.findSmallFactors(res.subtract(ONE), smallPrimes);
        }  while (residues.size() < 10);
        return  new PrimeAndFactors(res, residues);
    }

}
