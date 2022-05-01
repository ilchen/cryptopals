package com.cryptopals.set_9;

import com.cryptopals.set_6.DSAHelper;
import com.cryptopals.set_8.ECGroupElement;
import lombok.Data;

import java.math.BigInteger;

/**
 * This class implements multiplicative ElGamal encryption scheme atop an elliptic curve group E(F<sub>p</sub>)
 * some of whose elements can be mapped injectively to those of F<sub>p</sub>.
 *
 * Created by Andrei Ilchenko on 18-04-22.
 */
public class ECMultiplicativeElGamal {

    @Data
    public static final class  PublicKey {
        private final ECGroupElement G;
        private final BigInteger n;
        private final ECGroupElement   u;

        /**
         * Encrypts {@code msg} using the public key {@code u} and an ephemeral sk/pk pair.
         * @param msg  a message to encrypt, the total number of bits in the message must be one less than the number
         *             of bits in F<sub>p</sub>
         * @return  a two element array whose first element is the ephemeral public key &nu; and the second
         *          the {@code msg} encrypted as a member of E(F<sub>p</sub>)
         * @throws IllegalArgumentException  in case the number of bits in {@code msg} is more than one less than the
         *                                   number of bits in F<sub>p</sub>
         */
        public ECGroupElement[]  encrypt(byte[] msg) {
            // Generate ephemeral secret key
            BigInteger   beta = DSAHelper.generateK(n),
                         encodedMsg = DSAHelper.newBigInteger(msg); /* Takes care if the most significant bit of msg is 1 */
            FpMappableMontgomeryECGroup   fpMappableGroup = (FpMappableMontgomeryECGroup) G.group();
            ECGroupElement   v = G.scale(beta),  m = fpMappableGroup.mapFromFp(encodedMsg),
                             e = u.scale(beta).combine(m);
            return  new ECGroupElement[] {  v,  e  };
        }
    }

    // G is the base point generating the group of order n
    private final ECGroupElement   G;

    // n is the order of group E(Fp), d is the private key
    private final BigInteger   n,  d;


    /**
     * Constructs a sk/pk pair
     * @param g  a generator of a cyclic elliptic curve group
     * @param order  the order of the generator
     */
    public ECMultiplicativeElGamal(ECGroupElement g, BigInteger order) {
        this(g, order, DSAHelper.generateK(order));
    }

    /**
     * Constructs a Multiplicative ElGamal with a given sk/pk pair
     * @param g  a generator of a cyclic elliptic curve group
     * @param order  the order of the generator, it must be prime
     * @param d  the secret key to use
     * @throws IllegalArgumentException  in case {@code g} is not a member of an F<sub>p</sub> mappable elliptic curve
     *                                   or the order of {@code g} is not prime
     */
    public ECMultiplicativeElGamal(ECGroupElement g, BigInteger order, BigInteger d) {
        if (!(g.group() instanceof FpMappableMontgomeryECGroup)) {
            throw  new IllegalArgumentException("Group element " + g
                    + " is not member of a mappable elliptic curve group");
        }
        if (!order.isProbablePrime(64))  {
            throw  new IllegalArgumentException("The order of the generator is not prime");
        }
        G = g;     n = order;
        this.d = d;
    }

    public PublicKey getPublicKey() {
        return  new PublicKey(G, n, G.scale(d));
    }

    /**
     * Decrypts a multiplicative ElGamal ciphertext
     * @param megCipherText  a two element array whose first element is the ephemeral public key &nu; and the second
     *                       the {@code msg} encrypted as a member of E(F<sub>p</sub>)
     */
    public byte[]  decrypt(ECGroupElement[]  megCipherText) {
        ECGroupElement   m = megCipherText[1].combine(megCipherText[0].scale(d).inverse());
        FpMappableMontgomeryECGroup   fpMappableGroup = (FpMappableMontgomeryECGroup) G.group();
        BigInteger   encodedMsg = fpMappableGroup.mapToFp(m);
        return   encodedMsg.toByteArray();
    }
}
