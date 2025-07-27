package org.example.springsecurity.service;

import org.example.springsecurity.model.UserRequest;
import org.example.springsecurity.repository.UserAuthRepository;
import org.example.springsecurity.repository.securitydao.UserAuth;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserAuthService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserAuthRepository userAuthRepository;

    public UserDetails registerUser(UserRequest userRequest) {
        UserAuth userAuth = new UserAuth();
        userAuth.setUsername(userRequest.getUsername());
        userAuth.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        userAuth.setEnabled(true);
        userAuth.setRoles(userRequest.getRole());
        return userAuthRepository.save(userAuth);

    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userAuthRepository.findUserAuthByName(username).orElseThrow(() ->
            new UsernameNotFoundException("User not found with username: " + username));
    }
}
