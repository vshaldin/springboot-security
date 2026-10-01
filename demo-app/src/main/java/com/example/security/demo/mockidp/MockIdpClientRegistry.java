package com.example.security.demo.mockidp;

import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Hardcoded client_id/secret pairs for the client_credentials grant - a stand-in for Keycloak's
 * confidential client registration. Not for production use.
 */
@Component
public class MockIdpClientRegistry {

    private record Client(String tenant, String secret) {
    }

    private static final Map<String, Client> CLIENTS = Map.of(
            "internal-service", new Client("tenant-a", "internal-secret")
    );

    public boolean isValid(String clientId, String clientSecret, String tenant) {
        Client client = CLIENTS.get(clientId);
        return client != null && client.tenant().equals(tenant) && client.secret().equals(clientSecret);
    }
}
