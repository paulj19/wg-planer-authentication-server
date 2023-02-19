package com.wgplaner.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;

@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors().configurationSource(request -> {
                    CorsConfiguration corsConfiguration = new CorsConfiguration();
                    //corsConfiguration.setAllowedOrigins(List.of("127.0.0.1:19006")); //TODO set this later
                    corsConfiguration.setAllowedOrigins(Arrays.asList("http://127.0.0.1:19006")); //TODO set this later
                    corsConfiguration.setAllowCredentials(true);
                    corsConfiguration.setAllowedMethods(Arrays.asList(HttpMethod.GET.name(), HttpMethod.HEAD.name(), HttpMethod.POST.name(), HttpMethod.OPTIONS.name()));
                    //corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
                    corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
                    //corsConfiguration.applyPermitDefaultValues();
                    return corsConfiguration;
                }).and()
                .authorizeRequests().antMatchers("/actuator/**").permitAll().and()
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(withDefaults());

        //OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        //http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt).apply(authorizationServerConfigurer);
        return http.build();
    }

    @Bean
    UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

}
