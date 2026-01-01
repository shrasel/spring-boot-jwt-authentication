package com.example.jwt.security;

import com.example.jwt.service.JwtService;
import com.example.jwt.service.JwtService.JwtClaims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthFilter extends OncePerRequestFilter {
  private final JwtService jwtService;
  private final AuthenticationEntryPoint entryPoint;

  public JwtAuthFilter(JwtService jwtService, AuthenticationEntryPoint entryPoint) {
    this.jwtService = jwtService;
    this.entryPoint = entryPoint;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain
  ) throws ServletException, IOException {
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (header == null || !header.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    String token = header.substring(7);
    try {
      JwtClaims claims = jwtService.validateAccessToken(token);
      List<GrantedAuthority> authorities = claims.roles().stream()
          .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
          .collect(Collectors.toList());

      JwtUserPrincipal principal = new JwtUserPrincipal(
          claims.subject(),
          claims.roles(),
          claims.issuedAt(),
          claims.expiresAt(),
          claims.tokenId()
      );

      UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
          principal,
          null,
          authorities
      );
      SecurityContextHolder.getContext().setAuthentication(authentication);
      filterChain.doFilter(request, response);
    } catch (JwtService.JwtValidationException ex) {
      SecurityContextHolder.clearContext();
      entryPoint.commence(request, response, ex);
    }
  }
}
