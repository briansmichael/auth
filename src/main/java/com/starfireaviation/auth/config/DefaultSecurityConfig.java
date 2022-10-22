package com.starfireaviation.auth.config;

import com.starfireaviation.auth.service.SAAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {

    /**
     * SAAuthenticationProvider.
     */
    @Autowired
    private SAAuthenticationProvider saAuthenticationProvider;

    /**
     * SecurityFilterChain.
     *
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception when things go wrong
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**
     * Bind authentication provider.
     *
     * @param authenticationManagerBuilder AuthenticationManagerBuilder
     */
    @Autowired
    public void bindAuthenticationProvider(final AuthenticationManagerBuilder authenticationManagerBuilder) {
        authenticationManagerBuilder.authenticationProvider(saAuthenticationProvider);
    }
}
