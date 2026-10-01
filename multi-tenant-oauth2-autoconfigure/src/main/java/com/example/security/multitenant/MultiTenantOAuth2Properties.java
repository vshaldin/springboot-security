package com.example.security.multitenant;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties("app.security.multi-tenant")
public record MultiTenantOAuth2Properties(List<Tenant> tenants) {

    public MultiTenantOAuth2Properties {
        tenants = (tenants != null) ? List.copyOf(tenants) : List.of();
    }

    /**
     * @param issuerUri      expected {@code iss} claim; also used for OIDC discovery when {@code jwksUri} is absent
     * @param audience       expected {@code aud} claim for this tenant's resource server client
     * @param jwksUri        explicit JWKS endpoint; when set, avoids the blocking OIDC discovery call at startup
     * @param rolesClaimPath dot-separated path to the roles claim (e.g. {@code realm_access.roles}); defaults to
     *                       Spring's standard {@code scope}/{@code scp} handling when absent
     */
    public record Tenant(String issuerUri, String audience, String jwksUri, String rolesClaimPath) {
    }
}
