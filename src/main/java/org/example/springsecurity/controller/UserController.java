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
    @PutMapping("/role")
    public ResponseEntity<String> updateUser(@RequestParam("name") String username, @RequestParam("role") String role) {
        return userAuthService.updateUserRole(username, role);
    }

    @GetMapping("/hello")
    public String hello() {
        return "Hello! You have successfully logged in.";
    }

    @GetMapping("/")
    public String home() {
        return "Welcome to the home page!";
    }

    @GetMapping("/admin")
    public String admin() {
        return "Welcome to the admin page!";
    }
}
