package org.example.springsecurity.controller;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @PreAuthorize("hasAuthority('SCOPE_openid')")
    @GetMapping("/hello")
    public String hello() {
        return "Hello! You have successfully logged in.";
    }

    @GetMapping("/")
    public String home() {
        return "Welcome to the home page!";
    }

    @PreAuthorize("hasRole('#authentication.principal.authorities[0].authority') or hasRole('ROLE_ADMIN')")
    @PostAuthorize("returnObject='Welcome to the admin page!'")
    @GetMapping("/admin")
    public String admin() {
        return "Welcome to the admin page!";
    }
}
