package com.example.security.multitenant;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * Wires one {@link AuthenticationManager} per configured tenant (each with its own issuer,
 * audience and role-claim mapping) behind a single {@link JwtIssuerAuthenticationManagerResolver},
 * so a resource server can accept tokens from several independent Keycloak realms/instances.
 */
@AutoConfiguration
@ConditionalOnClass({JwtIssuerAuthenticationManagerResolver.class, HttpServletRequest.class})
@EnableConfigurationProperties(MultiTenantOAuth2Properties.class)
public class MultiTenantOAuth2AutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManagerResolver<HttpServletRequest> multiTenantAuthenticationManagerResolver(
            MultiTenantOAuth2Properties properties) {

        if (properties.tenants().isEmpty()) {
            // A resolver over an empty map would silently reject every request with a generic
            // 401 instead of surfacing the real problem, so fail loudly at startup instead.
            throw new IllegalStateException(
                    "No tenants configured under 'app.security.multi-tenant.tenants' - "
                            + "at least one tenant (issuer-uri, audience) is required.");
        }

        Map<String, AuthenticationManager> managersByIssuer = properties.tenants().stream()
                .collect(Collectors.toMap(
                        MultiTenantOAuth2Properties.Tenant::issuerUri,
                        this::buildAuthenticationManager,
                        (first, second) -> {
                            throw new IllegalStateException(
                                    "Duplicate tenant issuer-uri in 'app.security.multi-tenant.tenants'");
                        }
                ));

        return new JwtIssuerAuthenticationManagerResolver(managersByIssuer::get);
    }

    private AuthenticationManager buildAuthenticationManager(MultiTenantOAuth2Properties.Tenant tenant) {
        NimbusJwtDecoder decoder = buildDecoder(tenant);

        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
        provider.setJwtAuthenticationConverter(buildAuthenticationConverter(tenant));
        return provider::authenticate;
    }

    private NimbusJwtDecoder buildDecoder(MultiTenantOAuth2Properties.Tenant tenant) {
        NimbusJwtDecoder decoder;
        OAuth2TokenValidator<Jwt> issuerAndTimestamp;

        if (tenant.jwksUri() != null && !tenant.jwksUri().isBlank()) {
            // Explicit JWKS endpoint: no OIDC discovery call at startup, so a temporarily
            // unreachable IdP doesn't prevent this application's context from starting.
            decoder = NimbusJwtDecoder.withJwkSetUri(tenant.jwksUri()).build();
            issuerAndTimestamp = new DelegatingOAuth2TokenValidator<>(
                    JwtValidators.createDefault(),
                    new JwtIssuerValidator(tenant.issuerUri())
            );
        } else {
            decoder = NimbusJwtDecoder.withIssuerLocation(tenant.issuerUri()).build();
            issuerAndTimestamp = JwtValidators.createDefaultWithIssuer(tenant.issuerUri());
        }

        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(
                issuerAndTimestamp,
                new AudienceValidator(tenant.audience())
        );
        decoder.setJwtValidator(withAudience);
        return decoder;
    }

    private JwtAuthenticationConverter buildAuthenticationConverter(MultiTenantOAuth2Properties.Tenant tenant) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        if (tenant.rolesClaimPath() != null && !tenant.rolesClaimPath().isBlank()) {
            converter.setJwtGrantedAuthoritiesConverter(new ClaimPathRoleConverter(tenant.rolesClaimPath()));
        }
        return converter;
    }
}
