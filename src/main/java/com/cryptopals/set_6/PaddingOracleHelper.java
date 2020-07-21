package com.cryptopals.set_6;

import com.cryptopals.set_5.RSAHelper;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static com.cryptopals.set_6.DSAHelper.TWO;
import static java.math.BigInteger.*;

/**
 * Implements the attack outlined by Daniel Bleichenbacher in his
 * <a href="http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf">
 * Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1 paper</a>
 * <br/>
 *
 * Created by Andrei Ilchenko on 22-04-19.
 */
public class PaddingOracleHelper {
    @RequiredArgsConstructor @ToString
    private static class Interval implements Comparable<Interval> {
        private final BigInteger   lower,  upper;
        boolean  contains(Interval that) {
            return  lower.compareTo(that.lower) <= 0  &&  upper.compareTo(that.upper) >= 0;
        }
        boolean  intersects(Interval that) {
            return  lower.compareTo(that.lower) <= 0  &&  upper.compareTo(that.lower) >= 0
                    ||  that.lower.compareTo(lower) <= 0  &&  that.upper.compareTo(lower) >= 0;
        }

        Interval  intersection(Interval that) {
            return  intersects(that)  ?  new Interval(lower.max(that.lower), upper.min(that.upper)) : null;
        }

        /**
         * Strictly speaking this class is useless for using with collections requiring that
         * {@code equals} behaves consistently with {@code hashCode}.
         * However when stored in TreeMap-like collections, it will be a perfect fit for this task.
         */
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Interval that = (Interval) o;
            return  intersects(that);
        }

        @Override
        public int compareTo(Interval that) {
            if (intersects(that))  return  0;
            int   lowerDif = lower.compareTo(that.lower);
            return  lowerDif != 0  ?  lowerDif : upper.compareTo(that.upper);
        }
    }
    private final static BigInteger   THREE = valueOf(3L);
    private final BigInteger   cipherText;
    private final RSAHelper.PublicKey   pubKey;
    private final int   k;
    private final BigInteger   B,  _2B,  _3B,  _3B_MIN_1;
    private final Predicate<BigInteger>   paddingOracle;
    private BigInteger   s;
    private Collection<Interval>   intervals = new ArrayList<>();

    private PaddingOracleHelper(BigInteger cipherTxt, RSAHelper.PublicKey pk, Predicate<BigInteger> oracle) {
        cipherText = cipherTxt;
        pubKey = pk;
        k = (pk.getModulus().bitLength() + 7 & ~7) / 8;
        B = TWO.pow(8 * (k - 2));
        paddingOracle = oracle;
        _2B = TWO.multiply(B);
        _3B = THREE.multiply(B);
        _3B_MIN_1 = _3B.subtract(ONE);
        s = divideAndRoundUp(pk.getModulus(), _3B);
        intervals.add(new Interval(_2B,  _3B_MIN_1));
        assert oracle.test(pk.encrypt(_2B));
        assert oracle.test(pk.encrypt(_3B_MIN_1));
        assert !oracle.test(pk.encrypt(_3B));
    }

    /**
     * Implements steps 2a and 2b from Bleichenbacher's paper
     */
    private BigInteger  findNextS() {
        BigInteger   nextS = s;
        while (true) {
            if (paddingOracle.test(pubKey.encrypt(nextS).multiply(cipherText)))  return  s = nextS;
            nextS = nextS.add(ONE);
        }
//        return  s = Stream.<BigInteger>iterate(s, x -> x.add(BigInteger.ONE)).parallel()
//                .map(x -> pubKey.encrypt(x).multiply(cipherText))
//                .filter(paddingOracle).findFirst().orElseThrow(IllegalStateException::new);
    }

    /**
     * Implements step 2c from Bleichenbacher's paper
     */
    private BigInteger  step2c() {
        assert  intervals.size() == 1;
        Interval   interval = intervals.iterator().next();
        BigInteger   r = divideAndRoundUp(interval.upper.multiply(s).subtract(_2B).multiply(TWO), pubKey.getModulus()),
                     rn = r.multiply(pubKey.getModulus());

        while (true) {
            BigInteger   lower = divideAndRoundUp(_2B.add(rn), interval.upper),
                         upper = _3B.add(rn).divide(interval.lower);
            for (BigInteger nextS=lower; nextS.compareTo(upper) <= 0; nextS = nextS.add(ONE)) {
                if (paddingOracle.test(pubKey.encrypt(nextS).multiply(cipherText)))  return  s = nextS;
            }
            rn = rn.add(pubKey.getModulus());
        }
//        return  s = Stream.iterate(r, ri -> ri.add(BigInteger.ONE))
//                .flatMap(ri -> {
//                    BigInteger  rn = ri.multiply(pubKey.getModulus()), lower = divideAndRoundUp(_2B.add(rn), interval.upper),
//                                upper = _3B.add(rn).divide(interval.lower);
//                    return  Stream.iterate(lower, s -> s.add(ONE)).limit(upper.subtract(lower).longValueExact());
//                }).filter(s -> paddingOracle.test(pubKey.encrypt(s).multiply(cipherText))).findFirst().orElseThrow(IllegalStateException::new);
    }

    private int  step3() {
        // Only this step can give rise to multiple M intervals.
        List<Interval>   newIntervals = new ArrayList<>();
        System.out.printf("s =  %x%n", s);
        for (Interval interval : intervals) {
            System.out.printf("m \u2208 [%x,%n     %x]%n", interval.lower, interval.upper);
            BigInteger   lowerBound = divideAndRoundUp(interval.lower.multiply(s).subtract(_3B_MIN_1), pubKey.getModulus());
            BigInteger   upperBound = interval.upper.multiply(s).subtract(_2B).divide(pubKey.getModulus());
            System.out.printf("r \u2208 [%x,%n     %x]%n", lowerBound, upperBound);
            for (BigInteger r = lowerBound; r.compareTo(upperBound) <= 0; r = r.add(ONE)) {
                BigInteger   rn = r.multiply(pubKey.getModulus()),
                             a = divideAndRoundUp(_2B.add(rn), s),  b = _3B_MIN_1.add(rn).divide(s);
                if (a.compareTo(b) > 0)  continue;
                Interval   newInterval = new Interval(a.max(interval.lower), b.min(interval.upper));
//                newIntervals.compute(newInterval,
//                        (key, oldInterval) -> oldInterval == null  ?  newInterval : oldInterval.intersection(newInterval) );
                newIntervals.add(newInterval);
            }
        }
        intervals = newIntervals;
        int   numNewIntervals = newIntervals.size();
        // Only incrementing 's' for step 2b (more than one interval found)
        if (numNewIntervals > 1)  s = s.add(ONE);
        System.out.printf("Number of new intervals: %d%n%n", numNewIntervals);
        return  numNewIntervals;
    }

    public static BigInteger  solve(BigInteger cipherTxt, RSAHelper.PublicKey pk, Predicate<BigInteger> oracle) {
        PaddingOracleHelper   solver = new PaddingOracleHelper(cipherTxt, pk, oracle);
        solver.findNextS();
        solver.step3();
        int   numIntervals;
        Interval   interval;
        do {
            if (solver.intervals.size() > 1) {
                solver.findNextS();
            } else {
                solver.step2c();
            }
            numIntervals = solver.step3();
            interval = solver.intervals.iterator().next();
        } while (numIntervals > 1  ||  !interval.lower.equals(interval.upper));
        return  interval.lower;
    }

    /**
     * Computes &lceil;a/b&rceil;
     */
    private static BigInteger  divideAndRoundUp(BigInteger a, BigInteger b) {
        BigInteger[]   res = a.divideAndRemainder(b);
        return  res[1].equals(ZERO)  ?  res[0] : res[0].add(ONE);
    }
}
