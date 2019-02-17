package com.cryptopals.challenge_30_31;

import com.cryptopals.Set4;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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

@SpringBootApplication
public class Challenge31Application {
    public static void main(String[] args) {
        SpringApplication.run(Challenge31Application.class, args);
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
}
