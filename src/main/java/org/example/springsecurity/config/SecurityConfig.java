package org.example.springsecurity.config;

import org.example.springsecurity.filter.JwtValidationFilter;
import org.example.springsecurity.handler.OAuth2ResponseHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {


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
                .oauth2ResourceServer(oauth2ResourceServer -> {
                    oauth2ResourceServer.jwt(Customizer.withDefaults());
                })
                .addFilterBefore(new JwtValidationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
