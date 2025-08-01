package org.example.springsecurity.config;

import org.example.springsecurity.filter.OAuth2TokenValidationFilter;
import org.example.springsecurity.handler.OAuth2ResponseHandler;
import org.example.springsecurity.util.OAuth2AuthorizationUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private OAuth2AuthorizationUtil oAuth2AuthorizationUtil;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OAuth2ResponseHandler oauthResponseHandler) throws Exception {
        http.authorizeHttpRequests(authorizeRequests -> {
                    authorizeRequests
                            .anyRequest().authenticated();
                })
                .sessionManagement(sessionManagement -> {
                    sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                .csrf(CsrfConfigurer::disable)
                .oauth2Login(successfulLogin -> {
                    successfulLogin.successHandler(oauthResponseHandler);
                })
                .addFilterBefore(new OAuth2TokenValidationFilter(oAuth2AuthorizationUtil), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
