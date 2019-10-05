package com.cryptopals.set_8;

import com.cryptopals.set_7.MDHelper;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;


/**
 * Keeps track of all legit combinations of residues for moduli of the small subgroups groups of (a twist of) an
 * elliptic curve group.
 */
public class CRTCombinations implements Iterable<BigInteger[][]> {
    public enum MutationType {
        BOTH, EITHER, ONE
    }
    abstract class Mutation {
        final Mutation   prev;
        final int   idx;
        Mutation(int i, Mutation previous) {
            idx = i;     prev = previous;
        }
        abstract void  apply();
        abstract void  unApply();
        abstract boolean  isVallidApplied();
        abstract boolean  isVallidUnapplied();
        boolean  isChainValid() {
            return  (isVallidApplied() || isVallidUnapplied())  &&  (prev == null || prev.isChainValid());
        }
    }
    class  BothSetOrUnset extends Mutation {
        BothSetOrUnset(int i, Mutation prev) {
            super(i, prev);
        }
        @Override
        void apply() {
            residues[idx][0] = residues[idx][0].max(residues[idx][1].subtract(residues[idx][0]));
            residues[idx+1][0] = residues[idx+1][0].max(residues[idx+1][1].subtract(residues[idx+1][0]));
        }
        @Override
        void unApply() {
            residues[idx][0] = residues[idx][0].min(residues[idx][1].subtract(residues[idx][0]));
            residues[idx+1][0] = residues[idx+1][0].min(residues[idx+1][1].subtract(residues[idx+1][0]));

        }
        @Override
        boolean isVallidApplied() {
            return  residues[idx][0].compareTo(residues[idx][1].subtract(residues[idx][0])) > 0
                    &&  residues[idx+1][0].compareTo(residues[idx+1][1].subtract(residues[idx+1][0])) > 0;
        }
        @Override
        boolean isVallidUnapplied() {
            return  residues[idx][0].compareTo(residues[idx][1].subtract(residues[idx][0])) < 0
                    &&  residues[idx+1][0].compareTo(residues[idx+1][1].subtract(residues[idx+1][0])) < 0;
        }
    }
    class  EitherSetOrUnset extends Mutation {
        EitherSetOrUnset(int i, Mutation prev) {
            super(i, prev);
        }

        @Override
        void apply() {
            residues[idx][0] = residues[idx][0].min(residues[idx][1].subtract(residues[idx][0]));
            residues[idx+1][0] = residues[idx+1][0].max(residues[idx+1][1].subtract(residues[idx+1][0]));
        }
        @Override
        void unApply() {
            residues[idx][0] = residues[idx][0].max(residues[idx][1].subtract(residues[idx][0]));
            residues[idx+1][0] = residues[idx+1][0].min(residues[idx+1][1].subtract(residues[idx+1][0]));
        }
        @Override
        boolean isVallidApplied() {
            return  residues[idx][0].compareTo(residues[idx][1].subtract(residues[idx][0])) < 0
                    &&  residues[idx+1][0].compareTo(residues[idx+1][1].subtract(residues[idx+1][0])) > 0;
        }
        @Override
        boolean isVallidUnapplied() {
            return  residues[idx][0].compareTo(residues[idx][1].subtract(residues[idx][0])) > 0
                    &&  residues[idx+1][0].compareTo(residues[idx+1][1].subtract(residues[idx+1][0])) < 0;
        }
    }
    class  OneSetOrUnset extends Mutation {
        OneSetOrUnset(int i, Mutation prev) {
            super(i, prev);
        }
        @Override
        void apply() {
            residues[idx][0] = residues[idx][0].max(residues[idx][1].subtract(residues[idx][0]));
        }
        @Override
        void unApply() {
            residues[idx][0] = residues[idx][0].min(residues[idx][1].subtract(residues[idx][0]));
        }
        @Override
        boolean isVallidApplied() {
            return  residues[idx][0].compareTo(residues[idx][1].subtract(residues[idx][0])) > 0;
        }
        @Override
        boolean isVallidUnapplied() {
            return  residues[idx][0].compareTo(residues[idx][1].subtract(residues[idx][0])) < 0;
        }
    }

    private final BigInteger[][]   residues;
    private final ArrayList<Mutation>   mutations;
    public CRTCombinations(int numResidues) {
        residues = new BigInteger[numResidues][];
        mutations = new ArrayList<>();
    }

    /**
     * @param idx the index of this (b, r) combination
     * @param b  Bob's private key mod r
     * @param r  a modulus, typically a prime
     */
    public void  addResidue(int idx, BigInteger b, BigInteger r) {
        residues[idx] = new BigInteger[] { b, r };
    }

    public void  addMutation(int idx, MutationType mutationType) {
        Mutation   last = mutations.isEmpty()  ?  null : mutations.get(mutations.size() - 1);
        switch (mutationType) {
            case BOTH:
                mutations.add(new BothSetOrUnset(idx, last));
                break;
            case EITHER:
                mutations.add(new EitherSetOrUnset(idx, last));
                break;
            case ONE:
                mutations.add(new OneSetOrUnset(idx, last));
                break;
        }

    }

    /**
     * Can return a {@code null} value as the last element.
     */
    private class Iter implements Iterator<BigInteger[][]> {
        int   i = 0,   n = 1 << mutations.size();
        Iter() {
            mutations.forEach(Mutation::unApply);
        }

        @Override
        public boolean hasNext() {
            return i < n;
        }

        @Override
        public BigInteger[][] next() {
            for (int j=0; j < 32 - Integer.numberOfLeadingZeros(i); j++) {
                Mutation   head = mutations.get(j);
                if (MDHelper.getBit(i, j) == 1)  head.apply();
                else  head.unApply();
                if (!head.isChainValid()) {
                    i++;
                    return  hasNext()  ?  next() : null;
                }
            }
            i++;
            return  residues;
        }
    }
    @Override
    public Iterator<BigInteger[][]> iterator() {
        return  new Iter();
    }

}
