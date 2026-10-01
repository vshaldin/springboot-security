package com.example.security.demo.mockidp;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Stand-in for a real Keycloak realm: mints RS256 access tokens and exposes their public JWKS,
 * so the multi-tenant resource server and client setups can be exercised end-to-end without a
 * network dependency on an external IdP. Not for production use.
 */
@RestController
@RequestMapping("/mock-idp/{tenant}")
public class MockIdpController {

    private final MockIdpKeyRegistry keyRegistry;
    private final MockIdpClientRegistry clientRegistry;

    public MockIdpController(MockIdpKeyRegistry keyRegistry, MockIdpClientRegistry clientRegistry) {
        this.keyRegistry = keyRegistry;
        this.clientRegistry = clientRegistry;
    }

    @GetMapping("/jwks")
    public Map<String, Object> jwks(@PathVariable String tenant) {
        return keyRegistry.publicJwkSet(tenant).toJSONObject();
    }

    /**
     * Test-only shortcut: mints a token for an arbitrary subject/roles without any client
     * authentication, simulating "a user already has a token" for resource-server tests.
     */
    @GetMapping("/token")
    public Map<String, String> mintTestToken(
            @PathVariable String tenant,
            @RequestParam(defaultValue = "alice") String subject,
            @RequestParam(defaultValue = "USER") String roles,
            @RequestParam(required = false) String audience,
            @RequestParam(required = false) String issuer) throws Exception {

        // "issuer" lets a test claim to be a different tenant while still signing with this
        // tenant's key - the only way to exercise the cross-tenant-forgery case the resolver
        // is supposed to reject (signature won't verify against the claimed tenant's JWKS).
        String resolvedIssuer = (issuer != null) ? issuer : defaultIssuer(tenant);
        String resolvedAudience = (audience != null) ? audience : defaultAudience(tenant);
        List<String> roleList = List.of(roles.split(","));

        return Map.of("access_token", mintToken(tenant, resolvedIssuer, subject, resolvedAudience, roleList));
    }

    /**
     * Real OAuth2 token endpoint: {@code grant_type=client_credentials} with client
     * authentication via HTTP Basic, as Spring's {@code OAuth2AuthorizedClientManager} expects.
     */
    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> clientCredentialsToken(
            @PathVariable String tenant,
            @RequestParam("grant_type") String grantType,
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) throws Exception {

        if (!"client_credentials".equals(grantType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported grant_type: " + grantType);
        }

        String[] credentials = decodeBasicAuth(authorizationHeader);
        String clientId = credentials[0];
        String clientSecret = credentials[1];

        if (!clientRegistry.isValid(clientId, clientSecret, tenant)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid client credentials");
        }

        String accessToken = mintToken(
                tenant, defaultIssuer(tenant), clientId, defaultAudience(tenant), List.of("SERVICE"));

        return Map.of(
                "access_token", accessToken,
                "token_type", "Bearer",
                "expires_in", 3600);
    }

    private String mintToken(
            String tenant, String issuer, String subject, String audience, List<String> roleList) throws Exception {

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)));
        addRolesClaim(claims, tenant, roleList);

        RSAKey signingKey = keyRegistry.signingKey(tenant);
        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                claims.build());
        signedJwt.sign(new RSASSASigner(signingKey));
        return signedJwt.serialize();
    }

    // tenant-b mimics Keycloak's default nested realm_access.roles shape, tenant-a a flat
    // "roles" claim - on purpose, to demonstrate per-tenant role-claim-path configuration.
    private void addRolesClaim(JWTClaimsSet.Builder claims, String tenant, List<String> roleList) {
        if ("tenant-b".equals(tenant)) {
            claims.claim("realm_access", Map.of("roles", roleList));
        } else {
            claims.claim("roles", roleList);
        }
    }

    private String[] decodeBasicAuth(String header) {
        if (header == null || !header.startsWith("Basic ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing client credentials");
        }
        String decoded = new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8);
        int separatorIndex = decoded.indexOf(':');
        return new String[]{decoded.substring(0, separatorIndex), decoded.substring(separatorIndex + 1)};
    }

    private String defaultIssuer(String tenant) {
        return "http://localhost:8080/mock-idp/" + tenant;
    }

    private String defaultAudience(String tenant) {
        return "tenant-b".equals(tenant) ? "demo-api-b" : "demo-api";
    }
}
