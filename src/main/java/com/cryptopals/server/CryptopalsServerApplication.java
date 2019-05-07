package com.cryptopals.server;

import com.cryptopals.Set1;
import com.cryptopals.Set4;
import com.cryptopals.Set7;
import com.cryptopals.set_5.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.remoting.rmi.RmiServiceExporter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.net.MalformedURLException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
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
    public RmiServiceExporter rmiDHServiceExporter() {
        RmiServiceExporter rmiExporter = new RmiServiceExporter();
        rmiExporter.setService(new DiffieHellmanService());
        rmiExporter.setServiceName("DiffieHellmanService");
        rmiExporter.setServiceInterface(DiffieHellman.class);
        return rmiExporter;
    }

    @Bean
    public RmiServiceExporter rmiDHMITMServiceExporter2() throws RemoteException, MalformedURLException,
                                 NoSuchAlgorithmException, NoSuchPaddingException, NotBoundException {
        RmiServiceExporter rmiExporter = new RmiServiceExporter();
        rmiExporter.setService(new DiffieHellmanMITMService());
        rmiExporter.setServiceName("DiffieHellmanMITMService");
        rmiExporter.setServiceInterface(DiffieHellman.class);
        return rmiExporter;
    }

    @Bean
    public RmiServiceExporter rmiSRPServiceExporter() {
        RmiServiceExporter rmiExporter = new RmiServiceExporter();
        rmiExporter.setService(new SRPService());
        rmiExporter.setServiceName("SRPService");
        rmiExporter.setServiceInterface(SRP.class);
        return rmiExporter;
    }

    @Bean
    public Map<String, SecretKey>  getHeaderToKeyMap() {
        Map<String, SecretKey>   res = new HashMap<>();
        res.put("id100000012", Set1.YELLOW_SUBMARINE_SK);
        res.put("id100000013", Set7.BLACK_SUBMARINE_SK);
        return  Collections.unmodifiableMap(res);
    }

}
