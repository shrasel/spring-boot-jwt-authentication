package com.example.jwt.config;

import com.example.jwt.security.JwtAccessDeniedHandler;
import com.example.jwt.security.JwtAuthFilter;
import com.example.jwt.security.JwtAuthenticationEntryPoint;
import com.example.jwt.service.JwtService;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({JwtProperties.class, AppCorsProperties.class})
public class SecurityConfig {
  @Bean
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      JwtAuthFilter jwtAuthFilter,
      JwtAuthenticationEntryPoint entryPoint,
      AccessDeniedHandler accessDeniedHandler
  ) throws Exception {
    http
        .cors(Customizer.withDefaults())
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(entryPoint)
            .accessDeniedHandler(accessDeniedHandler))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(new AntPathRequestMatcher("/api/public/**")).permitAll()
            .requestMatchers(new AntPathRequestMatcher("/api/auth/**")).permitAll()
            .requestMatchers(HttpMethod.GET, "/api/admin").hasRole("ADMIN")
            .anyRequest().authenticated())
        .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public JwtAuthFilter jwtAuthFilter(JwtService jwtService, JwtAuthenticationEntryPoint entryPoint) {
    return new JwtAuthFilter(jwtService, entryPoint);
  }

  @Bean
  public JwtAuthenticationEntryPoint authenticationEntryPoint(com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
    return new JwtAuthenticationEntryPoint(objectMapper);
  }

  @Bean
  public AccessDeniedHandler accessDeniedHandler(com.fasterxml.jackson.databind.ObjectMapper objectMapper) {
    return new JwtAccessDeniedHandler(objectMapper);
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource(AppCorsProperties corsProperties) {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(corsProperties.allowedOrigins());
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }
}
