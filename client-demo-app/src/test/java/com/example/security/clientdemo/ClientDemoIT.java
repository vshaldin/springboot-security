package com.example.security.clientdemo;

import com.example.security.demo.DemoApplication;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Starts the real demo-app (resource server + mock IdP) alongside this client app in the same
 * JVM and drives both scenarios over real HTTP: a user-carried token being relayed downstream
 * unchanged, and this service minting its own client_credentials token when it is the initiator.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@AutoConfigureTestRestTemplate
class ClientDemoIT {

    private static ConfigurableApplicationContext demoAppContext;

    @Autowired
    private TestRestTemplate restTemplate;

    @BeforeAll
    static void startDemoApp() {
        // demo-app is a project() test dependency here, so its src/main/resources/application.yml
        // sits on this test's classpath alongside client-demo-app's OWN application.yml under the
        // same bare name - which one a plain classpath lookup resolves is classpath-order dependent
        // and not something to rely on. Point this bootstrap at a config file name that doesn't
        // exist anywhere and supply everything demo-app needs as command-line args (the highest
        // precedence Spring Boot property source), so this is deterministic regardless of that
        // collision.
        demoAppContext = new SpringApplicationBuilder(DemoApplication.class)
                .run(
                        "--spring.config.name=demo-app-test-bootstrap",
                        "--server.port=8080",
                        "--app.security.multi-tenant.tenants[0].issuer-uri=http://localhost:8080/mock-idp/tenant-a",
                        "--app.security.multi-tenant.tenants[0].audience=demo-api",
                        "--app.security.multi-tenant.tenants[0].jwks-uri=http://localhost:8080/mock-idp/tenant-a/jwks",
                        "--app.security.multi-tenant.tenants[0].roles-claim-path=roles",
                        "--app.security.multi-tenant.tenants[1].issuer-uri=http://localhost:8080/mock-idp/tenant-b",
                        "--app.security.multi-tenant.tenants[1].audience=demo-api-b",
                        "--app.security.multi-tenant.tenants[1].jwks-uri=http://localhost:8080/mock-idp/tenant-b/jwks",
                        "--app.security.multi-tenant.tenants[1].roles-claim-path=realm_access.roles"
                );
    }

    @AfterAll
    static void stopDemoApp() {
        demoAppContext.close();
    }

    @Test
    void relaysCallersTokenToDownstreamResourceServer() {
        String token = mintUserToken();

        ResponseEntity<String> response = restTemplate.exchange(
                "/gateway/hello", HttpMethod.GET, bearer(token), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"subject\":\"alice\"");
    }

    @Test
    void mintsOwnClientCredentialsTokenWhenSelfInitiated() {
        ResponseEntity<String> response = restTemplate.postForEntity("/internal/sync", null, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"subject\":\"internal-service\"");
    }

    @Test
    void gatewayRejectsRequestWithoutToken() {
        ResponseEntity<String> response = restTemplate.getForEntity("/gateway/hello", String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private String mintUserToken() {
        Map<?, ?> body = restTemplate.getForObject(
                "http://localhost:8080/mock-idp/tenant-a/token?subject=alice&roles=USER", Map.class);
        return body.get("access_token").toString();
    }

    private HttpEntity<Void> bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return new HttpEntity<>(headers);
    }
}
