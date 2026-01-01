package com.example.jwt.api.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
    @NotBlank String username,
    @NotBlank String password
) {}
