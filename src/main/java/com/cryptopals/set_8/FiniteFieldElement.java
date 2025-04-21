package com.cryptopals.set_8;

import java.math.BigInteger;

/**
 * Represents an element of an ordered finite field. Implementing classes must be immutable.
 */
public interface FiniteFieldElement<T extends FiniteFieldElement<T>> extends Comparable<FiniteFieldElement<T>> {
    /** @return  an object of the implementing class. */
    T  add(T e);
    /** @return  an object of the implementing class. */
    T  subtract(T e);
    /**
     * Computes this + this + ... + this {@code k} times
     * @return  an object of the implementing class.
     */
    T  times(BigInteger k);
    /** @return  an object of the implementing class. */
    T  multiply(T e);
    /** @return  an object of the implementing class. */
    T  modInverse();
    /**
     * Computes this * this * ... * this {@code k} times, i.e. computes this<sup>k</sup>
     * @return  an object of the implementing class.
     */
    T  scale(BigInteger k);
    /** @return  an object of the implementing class. */
    T  getAdditiveIdentity();
    /** @return  an object of the implementing class. */
    T  getMultiplicativeIdentity();
    /** @return  an uniformly distributed element of the implementing class. */
    T getRandomElement();
    BigInteger  getOrder();
    BigInteger  getCharacteristic();
}
