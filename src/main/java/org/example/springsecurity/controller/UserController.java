package org.example.springsecurity.controller;

import org.example.springsecurity.model.UserRequest;
import org.example.springsecurity.service.UserAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @Autowired
    UserAuthService userAuthService;

    @PostMapping("/register")
    public ResponseEntity<UserDetails> registerUser(@RequestBody UserRequest userRequest) {

        return ResponseEntity.ok(userAuthService.registerUser(userRequest));
    }

    @GetMapping("/")
    public ResponseEntity<String> home() {
        return ResponseEntity.ok("Welcome to the Spring Security Example");
    }
}
