package com.example.jwt.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "cors")
public record AppCorsProperties(List<String> allowedOrigins) {}
