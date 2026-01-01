package com.example.jwt.service;

import com.example.jwt.config.JwtProperties;
import com.example.jwt.service.UserService.UserRecord;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
  private static final Logger log = LoggerFactory.getLogger(JwtService.class);
  private static final Duration CLOCK_SKEW = Duration.ofSeconds(30);

  private final JwtProperties properties;
  private final MACSigner signer;
  private final MACVerifier verifier;

  public JwtService(JwtProperties properties) {
    this.properties = properties;
    byte[] secret = properties.secret().getBytes(StandardCharsets.UTF_8);
    if (secret.length < 32) {
      throw new IllegalArgumentException("JWT secret must be at least 32 bytes for HS256");
    }
    try {
      this.signer = new MACSigner(secret);
      this.verifier = new MACVerifier(secret);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to initialize JWT signer/verifier", e);
    }
  }

  public TokenData issueAccessToken(UserRecord user) {
    Instant now = Instant.now();
    Instant expiresAt = now.plus(Duration.ofMinutes(properties.accessTokenMinutes()));

    // JWT payload is Base64URL-encoded, not encrypted. Never store secrets in claims.
    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .subject(user.username())
        .issuer(properties.issuer())
        .audience(properties.audience())
        .issueTime(Date.from(now))
        .expirationTime(Date.from(expiresAt))
        .jwtID(UUID.randomUUID().toString())
        .claim("roles", user.roles())
        .claim("token_type", "access")
        .build();

    return sign(claims, expiresAt);
  }

  public TokenData issueRefreshToken(UserRecord user) {
    Instant now = Instant.now();
    Instant expiresAt = now.plus(Duration.ofDays(properties.refreshTokenDays()));

    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .subject(user.username())
        .issuer(properties.issuer())
        .audience(properties.audience())
        .issueTime(Date.from(now))
        .expirationTime(Date.from(expiresAt))
        .jwtID(UUID.randomUUID().toString())
        .claim("token_type", "refresh")
        .build();

    return sign(claims, expiresAt);
  }

  public JwtClaims validateAccessToken(String token) {
    return validateToken(token, "access");
  }

  public JwtClaims validateRefreshToken(String token) {
    return validateToken(token, "refresh");
  }

  private JwtClaims validateToken(String token, String expectedType) {
    try {
      SignedJWT signedJWT = SignedJWT.parse(token);
      if (!signedJWT.verify(verifier)) {
        throw new JwtValidationException("Invalid token signature");
      }

      JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
      validateStandardClaims(claims);

      String tokenType = claims.getStringClaim("token_type");
      if (!expectedType.equals(tokenType)) {
        throw new JwtValidationException("Unexpected token type");
      }

      List<String> roles = claims.getStringListClaim("roles");
      Instant issuedAt = claims.getIssueTime().toInstant();
      Instant expiresAt = claims.getExpirationTime().toInstant();

      return new JwtClaims(
          claims.getSubject(),
          roles == null ? List.of() : roles,
          issuedAt,
          expiresAt,
          claims.getJWTID(),
          tokenType
      );
    } catch (ParseException | JOSEException ex) {
      throw new JwtValidationException("Invalid token", ex);
    }
  }

  private void validateStandardClaims(JWTClaimsSet claims) {
    Instant now = Instant.now();

    if (claims.getSubject() == null || claims.getSubject().isBlank()) {
      throw new JwtValidationException("Missing subject");
    }
    if (!properties.issuer().equals(claims.getIssuer())) {
      throw new JwtValidationException("Invalid issuer");
    }
    if (claims.getAudience() == null || !claims.getAudience().contains(properties.audience())) {
      throw new JwtValidationException("Invalid audience");
    }
    if (claims.getIssueTime() == null) {
      throw new JwtValidationException("Missing issued-at");
    }
    if (claims.getJWTID() == null || claims.getJWTID().isBlank()) {
      throw new JwtValidationException("Missing token id");
    }
    if (claims.getExpirationTime() == null) {
      throw new JwtValidationException("Missing expiration");
    }
    Instant expiresAt = claims.getExpirationTime().toInstant();
    if (expiresAt.isBefore(now.minus(CLOCK_SKEW))) {
      throw new JwtValidationException("Token expired");
    }
  }

  private TokenData sign(JWTClaimsSet claims, Instant expiresAt) {
    try {
      SignedJWT signedJWT = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(),
          claims
      );
      signedJWT.sign(signer);
      String token = signedJWT.serialize();
      return new TokenData(token, expiresAt);
    } catch (JOSEException ex) {
      log.error("Failed to sign JWT", ex);
      throw new IllegalStateException("Failed to sign JWT", ex);
    }
  }

  public record TokenData(String token, Instant expiresAt) {}

  public record JwtClaims(
      String subject,
      List<String> roles,
      Instant issuedAt,
      Instant expiresAt,
      String tokenId,
      String tokenType
  ) {}

  public static class JwtValidationException extends org.springframework.security.core.AuthenticationException {
    public JwtValidationException(String message) {
      super(message);
    }

    public JwtValidationException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
