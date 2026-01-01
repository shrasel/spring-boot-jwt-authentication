package com.example.jwt.api.dto;

import java.time.Instant;
import java.util.List;

public record MeResponse(
    String subject,
    List<String> roles,
    Instant issuedAt,
    Instant expiresAt,
    String tokenId
) {}
