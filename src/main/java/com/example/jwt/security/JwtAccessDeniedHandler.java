package com.example.jwt.security;

import com.example.jwt.api.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtAccessDeniedHandler implements AccessDeniedHandler {
  private final ObjectMapper objectMapper;

  public JwtAccessDeniedHandler(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public void handle(
      HttpServletRequest request,
      HttpServletResponse response,
      AccessDeniedException accessDeniedException
  ) throws IOException {
    ErrorResponse body = new ErrorResponse(
        Instant.now(),
        HttpStatus.FORBIDDEN.value(),
        "Forbidden",
        accessDeniedException.getMessage(),
        request.getRequestURI()
    );

    response.setStatus(HttpStatus.FORBIDDEN.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    objectMapper.writeValue(response.getOutputStream(), body);
  }
}
