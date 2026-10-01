package com.example.security.clientdemo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Decides how to authenticate the outbound call to the downstream resource server: relay the
 * caller's own token when this service is itself fronting an already-authenticated user request,
 * or mint this service's own client_credentials token when it is the one initiating the call.
 */
@Component
public class DownstreamClient {

    private final RestClient restClient;
    private final OAuth2AuthorizedClientManager authorizedClientManager;

    public DownstreamClient(
            RestClient.Builder restClientBuilder,
            OAuth2AuthorizedClientManager authorizedClientManager,
            @Value("${app.downstream.base-url}") String downstreamBaseUrl) {
        this.restClient = restClientBuilder.baseUrl(downstreamBaseUrl).build();
        this.authorizedClientManager = authorizedClientManager;
    }

    public String callHello() {
        return restClient.get()
                .uri("/api/hello")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + resolveToken())
                .retrieve()
                .body(String.class);
    }

    private String resolveToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            return jwtAuthentication.getToken().getTokenValue();
        }
        return fetchOwnToken();
    }

    private String fetchOwnToken() {
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest
                .withClientRegistrationId("internal-service")
                .principal("client-demo-app")
                .build();
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(request);
        if (authorizedClient == null) {
            throw new IllegalStateException("Could not obtain a client_credentials token for 'internal-service'");
        }
        return authorizedClient.getAccessToken().getTokenValue();
    }
}
