package com.example.jwt.service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

@Service
public class TokenDenylistService {
  private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

  public void revoke(String jti, Instant expiresAt) {
    cleanupExpired();
    revoked.put(jti, expiresAt);
  }

  public boolean isRevoked(String jti) {
    cleanupExpired();
    return revoked.containsKey(jti);
  }

  private void cleanupExpired() {
    Instant now = Instant.now();
    revoked.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
  }
}
