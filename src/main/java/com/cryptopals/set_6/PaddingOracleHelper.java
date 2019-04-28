package com.cryptopals.set_6;

import com.cryptopals.set_5.RSAHelper;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Predicate;

import static com.cryptopals.set_6.DSAHelper.TWO;
import static java.math.BigInteger.*;

/**
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
            return  lower.compareTo(that.lower) <= 0  ||  upper.compareTo(that.upper) >= 0;
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
    private Collection<Interval>   intervals = new TreeSet<>();

    private PaddingOracleHelper(BigInteger cipherTxt, RSAHelper.PublicKey pk, Predicate<BigInteger> oracle) {
        cipherText = cipherTxt;
        pubKey = pk;
        k = (pk.getModulus().bitLength() + 7 & ~7) / 8;
        B = TWO.pow(8 * (k - 2));
        paddingOracle = oracle;
        _2B = TWO.multiply(B);
        _3B = THREE.multiply(B);
        _3B_MIN_1 = _3B.subtract(ONE);
        s = pk.getModulus().divide(_3B);
        intervals.add(new Interval(_2B,  _3B_MIN_1));
        assert oracle.test(pk.encrypt(_2B));
        assert oracle.test(pk.encrypt(_3B_MIN_1));
        assert !oracle.test(pk.encrypt(_3B));
    }

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

    private BigInteger  step2c() {
        assert  intervals.size() == 1;
        // In this step the current value of this.s doesn't matter as it gets set anew.
        Interval   interval = intervals.iterator().next();
        BigInteger   r[] = interval.upper.multiply(s).subtract(_2B).multiply(TWO).divideAndRemainder(pubKey.getModulus());
        if (!r[1].equals(ZERO))  r[0] = r[0].add(ONE);

        while (true) {
            BigInteger   lower[] = _2B.add(r[0].multiply(pubKey.getModulus())).divideAndRemainder(interval.upper),
                    upper = _3B.add(r[0].multiply(pubKey.getModulus()).divide(interval.lower)),  nextS;
            if (!lower[1].equals(ZERO))  lower[0] = lower[0].add(ONE);

            for (nextS = lower[0]; nextS.compareTo(upper) < 0; nextS = nextS.add(ONE)) {
                if (paddingOracle.test(pubKey.encrypt(nextS).multiply(cipherText)))  return  s = nextS;
            }
            r[0] = r[0].add(ONE);
        }
    }

    private int  step3() {
        // Only this step can give rise to multiple M intervals.
        TreeMap<Interval, Interval> newIntervals = new TreeMap<>();
        System.out.printf("s = %x%n", s);
        for (Interval interval : intervals) {
            System.out.printf("m \u2208 [%x,%n     %x]%n", interval.lower, interval.upper);
            BigInteger[]   lowerBound = interval.lower.multiply(s).subtract(_3B_MIN_1).divideAndRemainder(pubKey.getModulus());
            BigInteger     upperBound = interval.upper.multiply(s).subtract(_2B).divide(pubKey.getModulus());
            if (!lowerBound[1].equals(ZERO))  lowerBound[0] = lowerBound[0].add(ONE);
            System.out.printf("r \u2208 [%x,%n     %x]%n", lowerBound[0], upperBound);
            for (BigInteger r = lowerBound[0]; r.compareTo(upperBound) <= 0; r = r.add(ONE)) {
                BigInteger[]  a = _2B.add(r.multiply(pubKey.getModulus())).divideAndRemainder(s);
                BigInteger    b = _3B_MIN_1.add(r.multiply(pubKey.getModulus())).divide(s);
                if (a[1].compareTo(ZERO) != 0) a[0] = a[0].add(ONE);
                if (a[0].compareTo(b) > 0) continue;
                a[0] = a[0].max(interval.lower);
                b = b.min(interval.upper);
                Interval   newInterval = new Interval(a[0], b);
                newIntervals.compute(newInterval,
                        (key, oldInterval) -> oldInterval == null  ?  newInterval : oldInterval.intersection(newInterval) );
            }
        }
        intervals = newIntervals.values();
        s = s.add(ONE);
        System.out.printf("New intervals:%n%s%n%n", newIntervals.toString());
        return  newIntervals.size();
    }

//    private BigInteger  step3() {
//        TreeMap<Interval, Interval> newIntervals = new TreeMap<>();
//        if (intervals.size() != 1)  throw  new IllegalStateException("Mi-1 contains more than one interval");
//        Interval   interval = intervals.iterator().next();
//        BigInteger   rLower[] = interval.lower.multiply(s).subtract(_3B_MIN_1).divideAndRemainder(pubKey.getModulus()),
//                     rUpper = interval.upper.multiply(s).subtract(_2B).divide(pubKey.getModulus()),  r;
//        if (!rLower[1].equals(ZERO))  rLower[0] = rLower[0].add(ONE);
//
//        for (r = rLower[0]; r.compareTo(rUpper) <= 0; r = r.add(ONE)) {
//            BigInteger   lower[] = _2B.add(r.multiply(pubKey.getModulus())).divideAndRemainder(s),
//                         upper = _3B_MIN_1.add(r.multiply(pubKey.getModulus()).divide(s));
//            if (!lower[1].equals(ZERO))  lower[0] = lower[0].add(ONE);
//            newIntervals.put(new Interval(interval.lower.max(lower[0]), interval.upper.min(upper)));
//        }
//
//    }


    public static BigInteger  solve(BigInteger cipherTxt, RSAHelper.PublicKey pk, Predicate<BigInteger> oracle) {
        PaddingOracleHelper   solver = new PaddingOracleHelper(cipherTxt, pk, oracle);
        solver.findNextS();
        solver.step3();
        Interval   interval;
        do {
            if (solver.intervals.size() > 1) {
                solver.findNextS();
            } else {
                solver.step2c();
            }
            interval = solver.intervals.iterator().next();
        } while (solver.step3() > 1  ||  !interval.lower.equals(interval.upper));
        return  interval.lower;
    }
}
