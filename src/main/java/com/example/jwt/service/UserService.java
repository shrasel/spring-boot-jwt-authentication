package com.example.jwt.service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
  private final Map<String, UserRecord> users;
  private final PasswordEncoder passwordEncoder;

  public UserService(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
    this.users = Map.of(
        "admin", new UserRecord("admin", passwordEncoder.encode("admin123"), List.of("USER", "ADMIN")),
        "user", new UserRecord("user", passwordEncoder.encode("user123"), List.of("USER"))
    );
  }

  public Optional<UserRecord> authenticate(String username, String rawPassword) {
    UserRecord user = users.get(username);
    if (user == null) {
      return Optional.empty();
    }
    if (!passwordEncoder.matches(rawPassword, user.passwordHash())) {
      return Optional.empty();
    }
    return Optional.of(user);
  }

  public Optional<UserRecord> findByUsername(String username) {
    return Optional.ofNullable(users.get(username));
  }

  public record UserRecord(String username, String passwordHash, List<String> roles) {}
}
