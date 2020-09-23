package com.cryptopals.set_8;

import com.cryptopals.set_7.MDHelper;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.cryptopals.Set8.garnersAlgorithm;
import static java.util.stream.Collectors.toList;


/**
 * Keeps track of all legit combinations of residues for moduli of the small subgroups groups of (a twist of) an
 * elliptic curve group.
 */
public class CRTCombinations implements Iterable<BigInteger> {
    private final BigInteger[][]   residues;
    public CRTCombinations(BigInteger[][] residues) {
        this.residues = residues;
    }

    /**
     * Tries 2^residues.length combinations of the composite out of residues the outer class has been constructed with.
     */
    private class Iter implements Iterator<BigInteger> {
        final int   n = 1 << residues.length;
        int   i = 0;

        @Override
        public boolean hasNext() {
            return i < n;
        }

        @Override
        public BigInteger next() {
            if (i >= n)  throw new NoSuchElementException(String.format("%d >= %d", i, n));
            List<BigInteger[]>  adjustedResidues = IntStream.range(0, residues.length).mapToObj(
                    bitIdx -> (i >> bitIdx & 0x1) == 0
                            ? residues[bitIdx]
                            : new BigInteger[] { residues[bitIdx][1].subtract(residues[bitIdx][0]), residues[bitIdx][1]}
                            ).collect(toList());
            i++;
            return  garnersAlgorithm(adjustedResidues);
        }
    }
    @Override
    public Iterator<BigInteger> iterator() {
        return  new Iter();
    }

}
