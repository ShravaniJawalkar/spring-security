package org.example.springsecurity.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@Log4j2
public class OAuth2AuthorizationUtil {


    public String isTokenValid(String token) {
        String username = getIssuedIdFromToke(token);
        assert username != null;
        JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(username);
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaims().get("sub").toString();
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return null;
        }
    }

    private String getIssuedIdFromToke(String jwtToken) {
        try {
            String[] parts = jwtToken.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid token format");
            }
            String decodedPayload = new String(java.util.Base64.getDecoder().decode(parts[1]));
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> payloadMap = objectMapper.readValue(decodedPayload, Map.class);
            String issuedId = (String) payloadMap.get("iss");
            if (issuedId == null) {
                throw new IllegalArgumentException("Issued ID not found in token");
            }
            return issuedId;
        } catch (Exception e) {
            log.error("Error decoding JWT token: {}", e.getMessage());
            return null;

        }


    }
}
