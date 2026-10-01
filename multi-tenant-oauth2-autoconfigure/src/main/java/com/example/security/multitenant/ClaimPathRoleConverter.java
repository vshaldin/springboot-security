package com.example.security.multitenant;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Resolves roles from a dot-separated claim path, e.g. {@code realm_access.roles} or
 * {@code resource_access.my-client.roles} - Keycloak realms are free to nest roles differently
 * per client, so the path is per-tenant configuration rather than a fixed convention.
 */
public class ClaimPathRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String claimPath;

    public ClaimPathRoleConverter(String claimPath) {
        this.claimPath = claimPath;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Object current = jwt.getClaims();
        for (String segment : claimPath.split("\\.")) {
            if (!(current instanceof Map<?, ?> map)) {
                return List.of();
            }
            current = map.get(segment);
        }
        if (!(current instanceof Collection<?> roles)) {
            return List.of();
        }
        return roles.stream()
                .map(String::valueOf)
                .<GrantedAuthority>map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase(Locale.ROOT)))
                .collect(Collectors.toList());
    }
}
