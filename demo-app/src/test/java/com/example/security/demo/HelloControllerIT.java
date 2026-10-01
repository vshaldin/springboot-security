package com.example.security.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises the whole stack over real HTTP: mints tokens via the in-process mock IdP and calls
 * the protected endpoint through Spring Security, proving the multi-tenant wiring actually works
 * end-to-end rather than just compiling.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@AutoConfigureTestRestTemplate
class HelloControllerIT {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void acceptsTokenFromTenantAWithFlatRolesClaim() {
        String token = mintToken("tenant-a", "alice", "USER");

        ResponseEntity<Map> response = callHello(token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("subject", "alice");
        assertThat((List<String>) response.getBody().get("roles")).contains("ROLE_USER");
    }

    @Test
    void acceptsTokenFromTenantBWithNestedRolesClaim() {
        String token = mintToken("tenant-b", "bob", "ADMIN");

        ResponseEntity<Map> response = callHello(token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("subject", "bob");
        assertThat((List<String>) response.getBody().get("roles")).contains("ROLE_ADMIN");
    }

    @Test
    void rejectsTokenWithWrongAudience() {
        String token = mintTokenWithAudience("tenant-a", "eve", "USER", "some-other-api");

        ResponseEntity<String> response = callHelloRaw(token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsTokenSignedByWrongTenantKeyClaimingAnotherIssuer() {
        // Mallory only controls tenant-a's key, but claims to be tenant-b. The resolver picks
        // tenant-b's decoder based on the claimed iss, and tenant-b's JWKS can't verify a
        // signature made with tenant-a's private key - proving cross-tenant forgery is rejected.
        String forgedIssuer = URLEncoder.encode(
                "http://localhost:8080/mock-idp/tenant-b", StandardCharsets.UTF_8);
        String url = "/mock-idp/tenant-a/token?subject=mallory&roles=USER&issuer=" + forgedIssuer;
        Map<?, ?> body = restTemplate.getForObject(url, Map.class);
        String token = body.get("access_token").toString();

        ResponseEntity<String> response = callHelloRaw(token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rejectsRequestWithoutToken() {
        ResponseEntity<String> response = restTemplate.getForEntity("/api/hello", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private String mintToken(String tenant, String subject, String roles) {
        String url = "/mock-idp/%s/token?subject=%s&roles=%s".formatted(tenant, subject, roles);
        Map<?, ?> body = restTemplate.getForObject(url, Map.class);
        return body.get("access_token").toString();
    }

    private String mintTokenWithAudience(String tenant, String subject, String roles, String audience) {
        String url = "/mock-idp/%s/token?subject=%s&roles=%s&audience=%s"
                .formatted(tenant, subject, roles, audience);
        Map<?, ?> body = restTemplate.getForObject(url, Map.class);
        return body.get("access_token").toString();
    }

    private ResponseEntity<Map> callHello(String token) {
        return restTemplate.exchange("/api/hello", HttpMethod.GET, bearer(token), Map.class);
    }

    private ResponseEntity<String> callHelloRaw(String token) {
        return restTemplate.exchange("/api/hello", HttpMethod.GET, bearer(token), String.class);
    }

    private HttpEntity<Void> bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return new HttpEntity<>(headers);
    }
}
