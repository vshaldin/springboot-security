package com.example.security.clientdemo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Scenario "user-initiated": the caller's bearer token already passed this service's own
 * resource-server validation (see {@link SecurityConfig}) before this method runs, so
 * {@link DownstreamClient} finds it in the SecurityContext and relays it downstream unchanged.
 */
@RestController
public class GatewayController {

    private final DownstreamClient downstreamClient;

    public GatewayController(DownstreamClient downstreamClient) {
        this.downstreamClient = downstreamClient;
    }

    @GetMapping("/gateway/hello")
    public String gatewayHello() {
        return downstreamClient.callHello();
    }
}
