 ```java
//code-start

package com.example.loginapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@SpringBootApplication
public class LoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginApplication.class, args);
    }
}

//code-start

package com.example.loginapi.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            .and()
            .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/home").permitAll()
            .and()
            .logout()
                .permitAll();
    }
}

//code-start

package com.example.loginapi.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/private")
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // Security: Ensure credentials are encoded and verified securely
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        // Check if the user exists and password matches
        UserDetails user = authenticationManager.loadUserByUsername(username);
        if (encoder.matches(password, user.getPassword())) {
            // Security: Create authentication token here and return
            return "Logged in";
        } else {
            return "Login failed";
        }
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public Set<String> getUsers() {
        // Security: Only accessible by authorized users with ADMIN role
        return Set.of("admin", "user");
    }

    // Additional methods and classes can be implemented similarly
}

//code-end
```