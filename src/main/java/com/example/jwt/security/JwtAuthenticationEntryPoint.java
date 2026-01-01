package com.example.jwt.security;

import com.example.jwt.api.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
  private final ObjectMapper objectMapper;

  public JwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException
  ) throws IOException {
    ErrorResponse body = new ErrorResponse(
        Instant.now(),
        HttpStatus.UNAUTHORIZED.value(),
        "Unauthorized",
        authException.getMessage(),
        request.getRequestURI()
    );

    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    objectMapper.writeValue(response.getOutputStream(), body);
  }
}
