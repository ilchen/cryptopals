package com.cryptopals.server;

import com.cryptopals.Set1;
import com.cryptopals.Set4;
import com.cryptopals.Set7;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@SpringBootApplication
public class CryptopalsServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CryptopalsServerApplication.class, args);
    }

    @Bean
    public Set4  getEncryptor() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        SecretKey key = aesKeyGen.generateKey();
        return  new Set4(Cipher.ENCRYPT_MODE, key);
    }

    @Bean
    @Primary
    public Long  getDelayMillis() {
        return  Set4.DELAY_MILLIS;
    }

    @Bean
    @Primary
    public Integer  getHmacSignatureLength() {
        return  Set4.HMAC_SIGNATURE_LENGTH;
    }

    @Bean
    public Map<String, SecretKey>  getHeaderToKeyMap() {
        return Map.of("id100000012", Set1.YELLOW_SUBMARINE_SK, "id100000013", Set7.BLACK_SUBMARINE_SK);
    }

}
