package com.example.jwt.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record TokenRefreshRequest(
    @NotBlank @JsonProperty("refresh_token") String refreshToken
) {}
