package ru.home.hibernate.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
@EnableMethodSecurity
public class SecurityFilterChainImpl {

    // User Creation
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        // InMemoryUserDetailsManager setup with two users
        UserDetails admin = User.withUsername("Admin")
                .password(encoder.encode("Pass123"))
                .roles("ADMIN", "USER")
                .build();

        UserDetails user = User.withUsername("User")
                .password(encoder.encode("Pass321"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for simplicity
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/persons/by-city").permitAll() // Permit all access to /persons/by-city
                        .requestMatchers("/persons/by-age").authenticated() // Require authentication for /persons/by-age
                        .requestMatchers("/persons/by-name-surname").hasAnyRole("ADMIN") // Require Role "ADMIN" for /persons/by-name-surname
                )
                .formLogin(withDefaults()); // Enable form-based login

        return http.build();
    }

    // Password Encoding
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
