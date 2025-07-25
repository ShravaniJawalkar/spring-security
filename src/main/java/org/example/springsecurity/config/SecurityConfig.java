package org.example.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Using BCryptPasswordEncoder for password encoding
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder().username("dummyUser")
                .password(new BCryptPasswordEncoder().encode("dummyPassword")) // {noop} indicates no password encoder
                .roles("USER")
                .build();
        //here we are providing id of encrypted password, in this case it is bcrypt, so internally it will use DelegatingPasswordEncoder,
        // and then it will delegate it to BCryptPasswordEncoder
        UserDetails user1 = User.builder().username("adminUser")
                .password(new BCryptPasswordEncoder().encode("adminPassword"))
                .roles("ADMIN")
                .build();// {bcrypt} indicates bcrypt password encoder

        return new InMemoryUserDetailsManager(user, user1);
    }
}
