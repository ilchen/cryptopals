package com.cryptopals.set_8;

import com.cryptopals.Set5;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Represents a point on an Elliptic Curve group
 */
public interface ECGroupElement {
    BigInteger  getX();
    BigInteger  getY();
    ECGroupElement  getIdentity();
    ECGroupElement  inverse();
    ECGroupElement  combine(ECGroupElement that);

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
}
