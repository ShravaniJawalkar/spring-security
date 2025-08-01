package org.example.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {


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
