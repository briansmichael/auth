/*
 *  Copyright (C) 2022 Starfire Aviation, LLC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.starfireaviation.auth.service;

import com.starfireaviation.auth.model.SAUser;
import com.starfireaviation.auth.model.SAUserRepository;
import com.starfireaviation.common.CommonConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional
public class SAUserDetailsService implements UserDetailsService {

    /**
     * UserRepository.
     */
    @Autowired
    private SAUserRepository userRepository;

    /**
     * PasswordEncoder.
     *
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(CommonConstants.ELEVEN);
    }

    /**
     * Gets user details from an email address.
     *
     * @param email address
     * @return UserDetails
     * @throws UsernameNotFoundException when no user is found
     */
    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        SAUser user = userRepository.findByEmail(email);
        if (user != null) {
            return new User(user.getEmail(),
                    user.getPassword(),
                    user.isEnabled(),
                    true,
                    true,
                    true,
                    getAuthorities(List.of(user.getRole())));
        }
        throw  new UsernameNotFoundException("No User Found");
    }

    /**
     * Get authorities from list of roles.
     *
     * @param roles list
     * @return granted authorities
     */
    private Collection<? extends GrantedAuthority> getAuthorities(final List<String> roles) {
        return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
}
