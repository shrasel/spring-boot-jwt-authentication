package com.example.jwt.security;

import java.time.Instant;
import java.util.List;

public record JwtUserPrincipal(
    String subject,
    List<String> roles,
    Instant issuedAt,
    Instant expiresAt,
    String tokenId
) {}
