package org.example.springsecurity.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.token.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtValidationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public JwtValidationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = extractFromRequest(request);
        if (token != null) {
            JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(token);
            Authentication authenticationResult = authenticationManager.authenticate(jwtAuthenticationToken);
            if (authenticationResult.isAuthenticated()){
                SecurityContextHolder.getContext().setAuthentication(authenticationResult);
            }
        }
        filterChain.doFilter(request, response);
    }

    private String extractFromRequest(HttpServletRequest request) {
       String auth= request.getHeader("Authorization");
         if (auth != null && auth.startsWith("Bearer ")) {
              return auth.substring(7);
         }
         return null;
    }
}
