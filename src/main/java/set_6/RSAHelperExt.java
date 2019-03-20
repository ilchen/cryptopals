package set_6;

import com.cryptopals.set_5.RSAHelper;
import lombok.SneakyThrows;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

public class RSAHelperExt extends RSAHelper {
    private Set<ByteBuffer>   processed = ConcurrentHashMap.newKeySet();
    public RSAHelperExt() {
        super();
    }
    public RSAHelperExt(BigInteger e) {
        super(e);
    }

    @SneakyThrows
    public BigInteger  decrypt(BigInteger cipherTxt) {
        MessageDigest  sha = MessageDigest.getInstance("SHA-1");
        return  processed.add(ByteBuffer.wrap(sha.digest(cipherTxt.toByteArray())))  ?  cipherTxt.modPow(d, n)
                                                                                     :  BigInteger.ZERO;
    }
}
