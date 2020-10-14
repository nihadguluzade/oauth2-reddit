package io.github.nihadguluzade.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;


@Configuration
public class OAuth2LoginConfig {

    @EnableWebSecurity
    public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests(authorize -> authorize
                            .anyRequest().authenticated()
                    )
                    .oauth2Login()
                        .tokenEndpoint().accessTokenResponseClient(new RestOAuth2AccessTokenResponseClient(restOperations()))
                    .and()
                        .userInfoEndpoint().userService(new RestOAuth2UserService(restOperations()));
        }

    }

    @Bean
    public static RestOperations restOperations() {
        return new RestTemplate();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.redditClientRegistration());
    }

    private ClientRegistration redditClientRegistration() {
        return ClientRegistration.withRegistrationId("reddit")
                .clientId(client id)
                .clientSecret(client secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(Arrays.asList("identity"))
                .authorizationUri("https://www.reddit.com/api/v1/authorize")
                .tokenUri("https://www.reddit.com/api/v1/access_token")
                .userInfoUri("https://oauth.reddit.com/api/v1/me")
                .userNameAttributeName("name")
                .clientName("Reddit")
                .build();
    }

}
