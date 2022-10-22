package com.starfireaviation.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class SAAuthenticationProvider implements AuthenticationProvider {

    /**
     * SAUserDetailsService.
     */
    @Autowired
    private SAUserDetailsService saUserDetailsService;

    /**
     * PasswordEncoder.
     */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Authenticate.
     *
     * @param authentication Authentication
     * @return Authentication
     * @throws AuthenticationException when things go wrong
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();
        final UserDetails user = saUserDetailsService.loadUserByUsername(username);
        return checkPassword(user,password);
    }

    /**
     * Check password.
     *
     * @param user UserDetails
     * @param rawPassword raw password
     * @return Authentication
     */
    private Authentication checkPassword(final UserDetails user, final String rawPassword) {
        if(passwordEncoder.matches(rawPassword, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(user.getUsername(),
                    user.getPassword(),
                    user.getAuthorities());
        } else {
            throw new BadCredentialsException("Bad Credentials");
        }
    }

    /**
     * Supports.
     *
     * @param authentication authentication class
     * @return if authentication class is supported
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
