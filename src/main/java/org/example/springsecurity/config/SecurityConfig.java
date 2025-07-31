package org.example.springsecurity.config;

import org.example.springsecurity.filters.JwtAutheticationFilter;
import org.example.springsecurity.filters.JwtRefreshFilter;
import org.example.springsecurity.filters.JwtValidationFilter;
import org.example.springsecurity.provider.JwtAuthenticationProvider;
import org.example.springsecurity.utils.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtUtil jwtUtil;

    public SecurityConfig(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(UserDetailsService userDetailsService) {
        return new JwtAuthenticationProvider(jwtUtil,userDetailsService);
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService) throws Exception {
        return new ProviderManager(Arrays.asList(authenticationProvider(userDetailsService),
                jwtAuthenticationProvider(userDetailsService)));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        JwtAutheticationFilter jwtAutheticationFilter = new JwtAutheticationFilter(jwtUtil, authenticationManager);
        JwtValidationFilter jwt = new JwtValidationFilter(authenticationManager);
        JwtRefreshFilter jwtRefreshFilter = new JwtRefreshFilter(jwtUtil, authenticationManager);
        http.authorizeHttpRequests(auth-> auth.requestMatchers("/register").permitAll()
                .anyRequest().authenticated())
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtAutheticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(jwt, JwtAutheticationFilter.class)
                .addFilterAfter(jwtRefreshFilter, JwtValidationFilter.class)
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
