package org.example.springsecurity.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRequest {
    @JsonProperty("user_name")
    private String username;
    @JsonProperty("password")
    private String password;
    @JsonProperty("role")
    private String role;
}
