package com.example.security.clientdemo;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Scenario "self-initiated": this endpoint is open ({@link SecurityConfig} permits it), so there
 * is no user Authentication for {@link DownstreamClient} to find - it falls back to minting its
 * own client_credentials token.
 */
@RestController
public class InternalSyncController {

    private final DownstreamClient downstreamClient;

    public InternalSyncController(DownstreamClient downstreamClient) {
        this.downstreamClient = downstreamClient;
    }

    @PostMapping("/internal/sync")
    public String internalSync() {
        return downstreamClient.callHello();
    }
}
