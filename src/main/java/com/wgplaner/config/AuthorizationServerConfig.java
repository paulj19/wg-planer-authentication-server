package com.wgplaner.config;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.wgplaner.user.UserAuthProfile;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
public class AuthorizationServerConfig {
  public static String CLIENT_ID = "wg-planer";
  public static String CLIENT_PW = "secret";

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    // http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(Customizer.withDefaults());
    return http.cors().configurationSource(request -> {
      CorsConfiguration corsConfiguration = new CorsConfiguration();
      corsConfiguration.setAllowedOrigins(Arrays.asList("http://127.0.0.1:19006",
          "http://172.17.0.2",
          "https://auth.expo.io/",
          "https://auth.expo.io/wg-planer/login",
          "https://auth.expo.io/--/wg-planer/login",
          "exp://172.20.10.3:19000/--/wg-planer/login",
          "exp://192.168.1.9:8082/--/wg-planer/login",
          "exp://192.168.1.9:19000/--/wg-planer/login",
          "exp://192.168.1.9:19000/--/wg-planer/login",
          "exp://192.168.1.11:8082/--/wg-planer/login",
          "exp://192.168.1.11:19000/--/wg-planer/login",
          "exp://192.168.178.42:19000/--/wg-planer/login"));
      corsConfiguration.setAllowCredentials(true);
      corsConfiguration.setAllowedMethods(
          Arrays.asList(HttpMethod.GET.name(), HttpMethod.HEAD.name(), HttpMethod.POST.name(),
              HttpMethod.OPTIONS.name()));
      // corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
      corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
      corsConfiguration.setExposedHeaders(Arrays.asList("Authorization"));
      corsConfiguration.setMaxAge(1800L);
      return corsConfiguration;
    }).and()
        .exceptionHandling((exceptions) -> exceptions
            .authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")))
        // Accept access tokens for User Info and/or Client Registration
        .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt).build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.cors().configurationSource(request -> {
      CorsConfiguration corsConfiguration = new CorsConfiguration();
      corsConfiguration.setAllowedOrigins(Arrays.asList("http://127.0.0.1:19006",
          "http://172.17.0.2",
          "https://auth.expo.io/",
          "https://auth.expo.io/wg-planer/login",
          "https://auth.expo.io/--/wg-planer/login",
          "exp://172.20.10.3:19000/--/wg-planer/login",
          "exp://192.168.1.9:19000/--/wg-planer/login",
          "exp://192.168.1.9:8082/--/wg-planer/login",
          "exp://192.168.1.11:8082/--/wg-planer/login",

          "exp://192.168.178.42:19000/--/wg-planer/login"));
      corsConfiguration.setAllowCredentials(true);
      corsConfiguration.setAllowedMethods(Arrays.asList(HttpMethod.GET.name(), HttpMethod.HEAD.name(),
          HttpMethod.POST.name(), HttpMethod.OPTIONS.name()));
      corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
      corsConfiguration.setExposedHeaders(Arrays.asList("Authorization"));
      corsConfiguration.setMaxAge(1800L);
      // corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
      return corsConfiguration;
    }).and()
        .authorizeHttpRequests().requestMatchers("/actuator/**").permitAll().and()
        .authorizeHttpRequests().requestMatchers("/register/new").permitAll().and()
        .authorizeHttpRequests().requestMatchers("/login").permitAll().and()
        .authorizeHttpRequests().requestMatchers("/forgot-password").permitAll().and()
        .authorizeHttpRequests().requestMatchers("/password-recovery/**").permitAll().and()
        .authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
        .csrf().ignoringRequestMatchers("/register/new", "/password-recovery/**", "/login", "/forgot-password").and()
        // .formLogin(withDefaults());
        .formLogin()
        .loginPage("/login")
        .permitAll()
        .and()
        .logout()
        .permitAll();
    return http.build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId(CLIENT_ID)
        .clientSecret("$2a$12$CmTmrsmkRBAnftlgho6A1.VpLF/ZmIO1FfLNGTa6f7SBFhrFtCuTm")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://127.0.0.1:19006/wg-planer/login")
        .redirectUri("https://auth.expo.io/paulo48/wg-planer-mobile")
        .redirectUri("https://auth.expo.io/wg-planer/login")
        .redirectUri("https://auth.expo.io/--/wg-planer/login")
        .redirectUri("exp://172.20.10.3:19000/--/wg-planer/login")
        .redirectUri("exp://172.20.10.3:8081/--/wg-planer/login")
        .redirectUri("exp://192.168.178.42:19000/--/wg-planer/login")
        .redirectUri("exp://192.168.1.9:8082/--/wg-planer/login")
        .redirectUri("exp://192.168.1.9:19000/--/wg-planer/login")
        .redirectUri("exp://192.168.1.11:8082/--/wg-planer/login")
        .redirectUri("exp://192.168.1.11:19000/--/wg-planer/login")
        .redirectUri("wg-planer-mobile://wg-planer/login")
        .tokenSettings(tokenSettings())
        .scope(OidcScopes.OPENID)
        .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public TokenSettings tokenSettings() {
    return TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofMinutes(30L))
        .refreshTokenTimeToLive(Duration.ofDays(182L))
        .reuseRefreshTokens(false)
        .build();
  }

  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  private static RSAKey generateRsa() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
    return context -> {
      if (context.getTokenType().equals(ACCESS_TOKEN)) {
        Authentication principal = context.getPrincipal();
        context.getClaims().claim("oid", ((UserAuthProfile) principal.getPrincipal()).getId());
      }
    };
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }
}
