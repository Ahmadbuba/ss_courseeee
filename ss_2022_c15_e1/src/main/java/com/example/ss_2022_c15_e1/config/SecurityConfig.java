package com.example.ss_2022_c15_e1.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {
    @Value("${introspectionUri}")
    private String introspectionUri;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(rServer -> {
            rServer.opaqueToken(oToken -> {
                oToken.introspectionUri(introspectionUri);
                oToken.introspectionClientCredentials("client", "secret");
            });
        });
        http.authorizeHttpRequests(auth ->
                    auth.anyRequest().authenticated()
                );
        return http.build();
    }

}
