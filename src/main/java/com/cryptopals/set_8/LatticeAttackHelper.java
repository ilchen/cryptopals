package com.cryptopals.set_8;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.util.Arrays;
import java.util.stream.Stream;

import static java.math.BigDecimal.*;
import static com.cryptopals.set_8.RealMatrixOperations.lLL;

/**
 * This class implements the lattice basis reduction attack on ECDSA by utilizing
 * <a href="https://static.aminer.org/pdf/PDF/000/119/803/hardness_of_computing_the_most_significant_bits_of_secret_keys.pdf">
 *     the hidden number problem</a> formulated by Dan Boneh and Ramarathnam Venkatesanin 1996.
 * <br/>
 * Created by Andrei Ilchenko on 13-06-20.
 */
public class LatticeAttackHelper {
    private final BigDecimal  TWO_TO_THE_L_TH;
    private final BigDecimal[][]   pairs,  lattice,  reducedLattice;
    private final BigDecimal   q;
    private final int   l;

    /**
     * @param tuPairs an array of (t, u) pairs obtained from different ECDSA signatures with the same key and biased
     *                {@code k} nonces whose least significant {@code l} bits are zeros. Each ECDSA signature (r, s)
     *                gives rise to a (t, u) pair as follows: {@code t = r / ( s*2^l); u = H(q) / (-s*2^l)}
     * @param modulus the order of the base point used for this instance of ECDSA, it need not be prime
     * @param l  the number of the least signigicant zero bits in biased {@code k} nonces
     */
    public LatticeAttackHelper(BigInteger[][] tuPairs, BigInteger modulus, int l) {
        pairs = Stream.of(tuPairs).map(pair -> {
            BigDecimal[] r = new BigDecimal[2];
            r[0] = new BigDecimal(pair[0]);     r[1] = new BigDecimal(pair[1]);
            return r;
        }).toArray(BigDecimal[][]::new);
        q = new BigDecimal(modulus);
        TWO_TO_THE_L_TH = valueOf(1 << l);
        this.l = l;
        lattice = constructLattice();
        reducedLattice = lLL(lattice, BigDecimal.valueOf(.99));
    }

    public BigDecimal[][]  getLattice() {
        return   lattice;
    }
    public BigDecimal[][]  getReducedLattice() {
        return   reducedLattice;
    }

    public BigInteger  extractKey() {
        int   n = lattice.length;
        for (BigDecimal[] vec : reducedLattice) {
            if (lattice[n-1][n-1].equals(vec[n-1])) {
                return  vec[n-2].multiply(TWO_TO_THE_L_TH).negate().toBigInteger();
            }
        }
        return  BigInteger.ZERO;
    }

    private BigDecimal[][]  constructLattice() {
        BigDecimal[][]   res = new BigDecimal[pairs.length + 2][pairs.length + 2];
        res[pairs.length][pairs.length+1] = res[pairs.length+1][pairs.length] = ZERO;
        for (int i=0; i < pairs.length; i++) {
            Arrays.fill(res[i], ZERO);
            res[i][i] = q;
            res[pairs.length][i]   = pairs[i][0];
            res[pairs.length+1][i] = pairs[i][1];
        }

        // Take care of sentinel values
        // ct = 1/2^l
        res[pairs.length][pairs.length] = ONE.divide(TWO_TO_THE_L_TH, MathContext.UNLIMITED);
        // cu = q/2^l
        res[pairs.length+1][pairs.length+1] = q.divide(TWO_TO_THE_L_TH, MathContext.UNLIMITED);
        return  res;
    }

}
