package com.starfireaviation.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("auth")
public class ApplicationProperties {

    private String clientId;

    private String registeredClientId;

    private String clientSecret;

    private String authorizedRedirect;

    private String loginRedirect;
}
