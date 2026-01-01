package com.example.jwt.api;

import com.example.jwt.api.dto.LoginRequest;
import com.example.jwt.api.dto.LogoutRequest;
import com.example.jwt.api.dto.MessageResponse;
import com.example.jwt.api.dto.TokenRefreshRequest;
import com.example.jwt.api.dto.TokenResponse;
import com.example.jwt.service.JwtService;
import com.example.jwt.service.TokenDenylistService;
import com.example.jwt.service.UserService;
import com.example.jwt.service.UserService.UserRecord;
import jakarta.validation.Valid;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
  private static final Logger log = LoggerFactory.getLogger(AuthController.class);

  private final UserService userService;
  private final JwtService jwtService;
  private final TokenDenylistService denylistService;

  public AuthController(UserService userService, JwtService jwtService, TokenDenylistService denylistService) {
    this.userService = userService;
    this.jwtService = jwtService;
    this.denylistService = denylistService;
  }

  @PostMapping("/login")
  public TokenResponse login(@Valid @RequestBody LoginRequest request) {
    UserRecord user = userService.authenticate(request.username(), request.password())
        .orElseThrow(() -> new ErrorResponseException(HttpStatus.UNAUTHORIZED, ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid credentials"), null));

    JwtService.TokenData access = jwtService.issueAccessToken(user);
    JwtService.TokenData refresh = jwtService.issueRefreshToken(user);

    long expiresIn = Duration.between(Instant.now(), access.expiresAt()).getSeconds();
    log.info("Login success for user={}", user.username());

    return new TokenResponse(access.token(), refresh.token(), "Bearer", expiresIn);
  }

  @PostMapping("/refresh")
  public TokenResponse refresh(@Valid @RequestBody TokenRefreshRequest request) {
    JwtService.JwtClaims claims = jwtService.validateRefreshToken(request.refreshToken());
    if (denylistService.isRevoked(claims.tokenId())) {
      throw new ErrorResponseException(HttpStatus.UNAUTHORIZED, ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Refresh token revoked"), null);
    }

    UserRecord user = userService.findByUsername(claims.subject())
        .orElseThrow(() -> new ErrorResponseException(HttpStatus.UNAUTHORIZED, ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Unknown user"), null));

    JwtService.TokenData newAccess = jwtService.issueAccessToken(user);
    JwtService.TokenData newRefresh = jwtService.issueRefreshToken(user);
    denylistService.revoke(claims.tokenId(), claims.expiresAt());

    long expiresIn = Duration.between(Instant.now(), newAccess.expiresAt()).getSeconds();
    log.info("Refresh token rotated for user={}", user.username());

    return new TokenResponse(newAccess.token(), newRefresh.token(), "Bearer", expiresIn);
  }

  @PostMapping("/logout")
  public MessageResponse logout(@Valid @RequestBody LogoutRequest request) {
    JwtService.JwtClaims claims = jwtService.validateRefreshToken(request.refreshToken());
    denylistService.revoke(claims.tokenId(), claims.expiresAt());

    log.info("Refresh token revoked for user={}", claims.subject());
    return new MessageResponse("Logged out. Refresh token revoked until expiry.");
  }
}
