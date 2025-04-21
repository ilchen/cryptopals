package com.cryptopals.server;

import java.net.MalformedURLException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.NoSuchAlgorithmException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.cryptopals.set_5.DiffieHellmanService;
import com.cryptopals.set_5.DiffieHellmanMITMService;
import com.cryptopals.set_5.SRPService;
import com.cryptopals.set_8.DiffieHellmanBobService;
import com.cryptopals.set_8.ECDiffieHellmanBobService;

import javax.crypto.NoSuchPaddingException;

@Configuration
class RmiServerConfig {

    @Bean
    public Registry rmiRegistry() throws RemoteException, MalformedURLException, NotBoundException,
            NoSuchPaddingException, NoSuchAlgorithmException {
        Registry registry = LocateRegistry.createRegistry(1099);
        bindRmiServices(registry);
        return registry;
    }

    private void bindRmiServices(Registry registry) throws RemoteException, MalformedURLException, NotBoundException,
            NoSuchPaddingException, NoSuchAlgorithmException {
        registry.rebind("DiffieHellmanService", new DiffieHellmanService());
        registry.rebind("DiffieHellmanMITMService", new DiffieHellmanMITMService());
        registry.rebind("DiffieHellmanBobService", new DiffieHellmanBobService());
        registry.rebind("ECDiffieHellmanBobService", new ECDiffieHellmanBobService());
        registry.rebind("SRPService", new SRPService());

        System.out.println("RMI services bound successfully.");
    }
}