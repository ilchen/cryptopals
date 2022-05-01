package com.cryptopals.set_8;

import com.cryptopals.Set5;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.function.BiFunction;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

/**
 * Represents a point on an Elliptic Curve group E(F<sub>p</sub>)
 */
public interface ECGroupElement {
    BigInteger  getX();
    BigInteger  getY();
    ECGroupElement  getIdentity();
    ECGroupElement  inverse();
    ECGroupElement      combine(ECGroupElement that);
    ECGroup  group();

    /** Returns the x coordinate of kP where P is this point */
    BigInteger  ladder(BigInteger k);

    default ECGroupElement  scale(BigInteger k) {
        ECGroupElement res = getIdentity(),  x = this;
        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (Set5.isOdd(k))  res = res.combine(x);
            x = x.combine(x);
            k = k.shiftRight(1);
        }
        return  res;
    }

    default byte[]  toByteArray() {
        if (this.equals(getIdentity())) {
            return  new byte[0];
        } else {
            byte[]   xBytes = getX().toByteArray(),  yBytes = getY().toByteArray(),  res;
            res = Arrays.copyOf(xBytes, xBytes.length + yBytes.length);
            System.arraycopy(yBytes, 0, res, xBytes.length, yBytes.length);
            return  res;
        }
    }

    /**
     * Calculates the discrete log of {@code y} base this point using J.M. Pollard's Lambda Method
     * for Catching Kangaroos, as outlined in Section 3 of <a href="https://arxiv.org/pdf/0812.0789.pdf">this paper</a>.
     * I chose the algorithm's parameter N in such a way as ot ensure the probability of the method succeeding is 98%.
     *
     * @param y  the parameter whose dlog needs to be found
     * @param b  upper bound (inclusive) that the logarithm lies in
     * @param f  a pseudo-random function mapping from set {1, 2, ..., p-1} to set {0, 1, ..., p-1}
     * @return  the dlog of {@code y} if the algorithm succeeds, {@link BigInteger#ZERO} otherwise
     */
    default BigInteger  dlog(ECGroupElement y, BigInteger b, BiFunction<ECGroupElement, Integer, BigInteger> f) {

        // k is calculated based on a formula in this paper: https://arxiv.org/pdf/0812.0789.pdf
        double   d = Math.log(Math.sqrt(b.doubleValue())) / Math.log(2);
        d += Math.log(d) / Math.log(2) + 2;
        int   k = (int) Math.ceil(d);

        BigInteger   n = ZERO;
        for (int i=0; i < k; i++) {
            n = n.add(f.apply(group().createPoint(BigInteger.valueOf(i), BigInteger.valueOf(i)), k));
        }
        n = n.divide(BigInteger.valueOf(k >> 2)); // 4 times the mean => probability 0.98 of succeeding
        System.out.printf("k=%d, N=%d%n", k, n);

        BigInteger   xt = ZERO;
        ECGroupElement   yt = scale(b);
        for (BigInteger i=ZERO; i.compareTo(n) < 0; i=i.add(ONE)) {
            xt = xt.add(f.apply(yt, k));
            //yt = yt.multiply(g.modPow(f(yt, k), p)).remainder(p);
            yt = yt.combine(scale(f.apply(yt, k)));
        }
        System.out.printf("xt=%d, upperBound=%d%nyt=%s%n", xt, b.add(xt), yt);

        BigInteger   xw = ZERO;
        ECGroupElement   yw = y;
        while (xw.compareTo(b.add(xt)) < 0) {
            xw = xw.add(f.apply(yw, k));
            //yw = yw.multiply(g.modPow(f(yw, k), p)).remainder(p);
            yw = yw.combine(scale(f.apply(yw, k)));
            if (yw.equals(yt))  {
                return  b.add(xt).subtract(xw);
            }
        }
        return  ZERO;
    }

    /**
     * A most simplistic pseudo random function from set {1, 2, ..., p-1} to set {0, 1, ..., k-1},
     * which is used by J.M. Pollard as an example in his paper
     */
    public static BigInteger  f(ECGroupElement y, int k) {
        return BigInteger.valueOf(1L << y.getX().remainder(BigInteger.valueOf(k)).intValue());
    }

}
