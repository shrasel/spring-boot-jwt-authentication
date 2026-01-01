package com.example.jwt.api;

import com.example.jwt.api.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {
  @ExceptionHandler(ErrorResponseException.class)
  public ResponseEntity<ErrorResponse> handleErrorResponseException(
      ErrorResponseException ex,
      HttpServletRequest request
  ) {
    ErrorResponse body = new ErrorResponse(
        Instant.now(),
        ex.getStatusCode().value(),
        ex.getStatusCode().toString(),
        ex.getBody().getDetail(),
        request.getRequestURI()
    );
    return ResponseEntity.status(ex.getStatusCode()).body(body);
  }
}
