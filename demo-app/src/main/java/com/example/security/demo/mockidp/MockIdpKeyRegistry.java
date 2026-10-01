package com.example.security.demo.mockidp;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Stands in for two independent Keycloak realms: each tenant gets its own RSA signing key,
 * so the demo can prove that tokens are validated against the matching tenant's key material.
 */
@Component
public class MockIdpKeyRegistry {

    public static final List<String> TENANTS = List.of("tenant-a", "tenant-b");

    private final Map<String, RSAKey> keysByTenant;

    public MockIdpKeyRegistry() {
        this.keysByTenant = TENANTS.stream()
                .collect(Collectors.toUnmodifiableMap(tenant -> tenant, this::generateKey));
    }

    private RSAKey generateKey(String tenant) {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID(tenant + "-key")
                    .keyUse(KeyUse.SIGNATURE)
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate signing key for tenant " + tenant, e);
        }
    }

    public RSAKey signingKey(String tenant) {
        RSAKey key = keysByTenant.get(tenant);
        if (key == null) {
            throw new IllegalArgumentException("Unknown tenant: " + tenant);
        }
        return key;
    }

    public JWKSet publicJwkSet(String tenant) {
        return new JWKSet(signingKey(tenant).toPublicJWK());
    }
}
