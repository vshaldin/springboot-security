package com.example.security.demo;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class HelloController {

    @GetMapping("/api/hello")
    public Map<String, Object> hello(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Map.of(
                "issuer", jwt.getIssuer().toString(),
                "subject", jwt.getSubject(),
                "roles", roles
        );
    }
}
