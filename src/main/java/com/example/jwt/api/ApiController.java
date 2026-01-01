package com.example.jwt.api;

import com.example.jwt.api.dto.MeResponse;
import com.example.jwt.security.JwtUserPrincipal;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {
  @GetMapping("/public/ping")
  public Map<String, String> ping() {
    return Map.of("message", "pong");
  }

  @GetMapping("/me")
  public MeResponse me(Authentication authentication) {
    JwtUserPrincipal principal = (JwtUserPrincipal) authentication.getPrincipal();
    return new MeResponse(
        principal.subject(),
        principal.roles(),
        principal.issuedAt(),
        principal.expiresAt(),
        principal.tokenId()
    );
  }

  @GetMapping("/admin")
  public Map<String, String> admin() {
    return Map.of("message", "Hello, admin!");
  }
}
