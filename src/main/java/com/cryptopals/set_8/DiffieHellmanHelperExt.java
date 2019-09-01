package com.cryptopals.set_8;

import com.cryptopals.set_5.DiffieHellmanHelper;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

/**
 * Represents a group Z<sub>p</sub><sup>*</sup> that is suitable for the Diffie Hellman protocol.
 * This class allows to construct cryptographically secure instances of Z<sub>p</sub><sup>*</sup> based on the advice
 * in Section 11.6 of "Cryptography Engineering, 2<sup>nd</sup> edition" by Niels Ferguson, Bruce Schneier,
 * and Tadayoshi Kohno.
 */
final public class DiffieHellmanHelperExt extends DiffieHellmanHelper {
    private static final int   NUM_BITS_Q = 42,  CERTAINTY = 100;
    private final BigInteger   q;

    public static DiffieHellmanHelperExt  newInstance() {
        return  newInstance(NUM_BITS, NUM_BITS_Q);
    }

    /**
     * Constructs a new instance of this class whose Z<sub>p</sub><sup>*</sup> group is defined as follows:
     * <ul>
     *     <li>{@code p} is a {@code nBitsP}-bits prime meeting the following  requirement: {@code p = Nq + 1},
     *     where {@code q} is a {@code nBitsQ}-bits prime.</li>
     *     <li>The generator {@code g} is a random member of Z<sub>p</sub><sup>*</sup> that has an order of {@code q}</li>
     * </ul>
     * @param nBitsP  number of bits in prime {@code p}
     * @param nBitsQ  number of bits in prome {@code q}
     */
    public static DiffieHellmanHelperExt  newInstance(int nBitsP, int nBitsQ) {
        if (nBitsQ >= nBitsP) {
            throw  new IllegalArgumentException("Number of bits in p must be greater than those in q");
        }
        if (nBitsQ < 20) {
            throw  new IllegalArgumentException("q must be at least 20 bits");
        }
        if (nBitsP < 128) {
            throw  new IllegalArgumentException("p must be at least 128 bits");
        }
        final Random secRandGen = new SecureRandom();
        BigInteger  q = BigInteger.probablePrime(nBitsQ, secRandGen),  N,  p,  g;
        do {
            N = new BigInteger(NUM_BITS - nBitsQ, secRandGen);
            p = N.multiply(q).add(ONE);
        } while (p.bitLength() != nBitsP  ||  !p.isProbablePrime(CERTAINTY));

        do {  // We need to exclude the trivial subgroups
            g = new BigInteger(nBitsP, secRandGen).mod(p).modPow(N, p);
        } while (g.equals(ONE) || !g.modPow(q, p).equals(ONE));
        return  new DiffieHellmanHelperExt(p, g, q);
    }

    public DiffieHellmanHelperExt(BigInteger p, BigInteger g, BigInteger q) {
        super(p, g);
        BigInteger   pMin1 = p.subtract(ONE),  r[] = pMin1.divideAndRemainder(q);
        if (!r[1].equals((ZERO))) {
            throw  new IllegalArgumentException(q + " is not a factor of p-1: " + pMin1);
        }
        this.q = q;
    }

    public BigInteger  getGenOrder() {
        return  q;
    }

    /**
     * Finds all factors of the quotient of p-1 and {@link DiffieHellmanHelperExt::q} that are smaller than 2^16
     * and greater than 4 (if any)
     */
    public List<BigInteger>  findSmallFactors() {
        BigInteger   pMin1 = p.subtract(ONE),  r[] = pMin1.divideAndRemainder(q);

        List<BigInteger>   factors = IntStream.range(2, 1 << 16) /* Finding all divisors of r */
                .filter(i -> r[0].remainder(BigInteger.valueOf(i)).equals(ZERO))
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

    @Override
    public BigInteger generateExp() {
        return super.generateExp().mod(q);
    }
}
