package org.example.springsecurity.filter;

import ch.qos.logback.core.util.StringUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.springsecurity.util.OAuth2AuthorizationUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class OAuth2TokenValidationFilter extends OncePerRequestFilter {
    private final OAuth2AuthorizationUtil oAuth2AuthorizationUtil;

    public OAuth2TokenValidationFilter(OAuth2AuthorizationUtil oAuth2AuthorizationUtil) {
        this.oAuth2AuthorizationUtil = oAuth2AuthorizationUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = extractAndValidateToken(request);
        if (token != null) {
            String subject = oAuth2AuthorizationUtil.isTokenValid(token);
            if (StringUtil.isNullOrEmpty(subject)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
                return; // Stop further processing if the token is invalid
            }
            List<GrantedAuthority> authorities = List.of();
            Authentication authentication = new UsernamePasswordAuthenticationToken(subject, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        filterChain.doFilter(request, response);


    }

    private String extractAndValidateToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null; // or throw an exception if token is required
    }
}
