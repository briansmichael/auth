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

package com.starfireaviation.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("auth")
public class ApplicationProperties {

    /**
     * Client ID.
     */
    private String clientId;

    /**
     * Registered Client ID.
     */
    private String registeredClientId;

    /**
     * Client Secret.
     */
    private String clientSecret;

    /**
     * Authorized Redirect.
     */
    private String authorizedRedirect;

    /**
     * Login Redirect.
     */
    private String loginRedirect;
}
