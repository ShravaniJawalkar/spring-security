package org.example.springsecurity.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class JwtValidationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = extractToken(request);
        if (token != null) {
            try {
                JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation("https://gitlab.com"); // Use your issuer
                Jwt jwt = jwtDecoder.decode(token);
                String username = jwt.getSubject();
                Object rolesObj = jwt.getClaims().get("roles");
                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                if (rolesObj instanceof List rolesList) {
                    for (Object role : rolesList) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                    }
                } else if (rolesObj instanceof String roleStr) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + roleStr));
                }
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Invalid JWT token");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        String authToken = null;
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            authToken = bearerToken.substring(7);
        }
        return authToken;
    }

}
