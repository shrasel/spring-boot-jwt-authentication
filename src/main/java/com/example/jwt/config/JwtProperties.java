package com.example.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
    String secret,
    String issuer,
    String audience,
    long accessTokenMinutes,
    long refreshTokenDays
) {}
