package org.example.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests -> {
                    authorizeRequests.requestMatchers("/register").permitAll().
                            requestMatchers("/login").permitAll()
                            .requestMatchers("/role").permitAll()
                            .requestMatchers("/favicon.ico").permitAll()
                            .requestMatchers("/error").permitAll()
                            .requestMatchers("/hello").hasAnyRole("USER","ADMIN")
                            .requestMatchers("/admin").hasRole("ADMIN").anyRequest().authenticated();
                })
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/register")
                        .ignoringRequestMatchers("/role")
                )
                .formLogin(form -> form
                        .defaultSuccessUrl("/hello", true)
                )
                .sessionManagement(session->{
                    session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS).maximumSessions(1)
                            .maxSessionsPreventsLogin(true)
                            .expiredUrl("/login?expired=true");
                })
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
