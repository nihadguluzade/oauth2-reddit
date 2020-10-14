package io.github.nihadguluzade.oauth2.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class RestOAuth2AccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private RestOperations restOperations;
    private final String USER_AGENT = ChangeMeClient/0.1 by YourUsername;
    private String authorizationResponseBaseUri;

    public RestOAuth2AccessTokenResponseClient(RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest oAuth2AuthorizationCodeGrantRequest) throws OAuth2AuthenticationException {
        ClientRegistration clientRegistration = oAuth2AuthorizationCodeGrantRequest.getClientRegistration();

        String tokenUri = clientRegistration.getProviderDetails().getTokenUri();

        HttpHeaders headers = new HttpHeaders();
        headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add(HttpHeaders.USER_AGENT, USER_AGENT);

        String code = oAuth2AuthorizationCodeGrantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode();

        ResponseEntity<AccessResponse> response = restOperations.exchange(tokenUri, HttpMethod.POST, new HttpEntity<>("grant_type=authorization_code&code=" + code + "&redirect_uri=http://localhost:8080/login/oauth2/code/reddit", headers), AccessResponse.class);

        AccessResponse accessResponse = response.getBody();

        Set<String> scopes = accessResponse.getScopes().isEmpty() ?
                oAuth2AuthorizationCodeGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getScopes() : accessResponse.getScopes();

        return OAuth2AccessTokenResponse.withToken(accessResponse.getAccessToken())
                .tokenType(accessResponse.getTokenType())
                .expiresIn(accessResponse.getExpiresIn())
                .scopes(scopes)
                .build();

    }

    static class AccessResponse {
        @JsonProperty("access_token")
        private String accessToken;

        @JsonProperty("token_type")
        private String tokenType;

        @JsonProperty("expires_in")
        private int expiresIn;

        @JsonProperty("refresh_token")
        private String refreshToken;

        private String scope;

        public AccessResponse() {}

        AccessResponse(String accessToken, String tokenType, int expiresIn, String refreshToken, String scope) {
            this.accessToken = accessToken;
            this.tokenType = tokenType;
            this.expiresIn = expiresIn;
            this.refreshToken = refreshToken;
            this.scope = scope;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public OAuth2AccessToken.TokenType getTokenType() {
            return OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(tokenType) ? OAuth2AccessToken.TokenType.BEARER : null;
        }

        public int getExpiresIn() {
            return expiresIn;
        }

        public Set<String> getScopes() {
            return StringUtils.isEmpty(scope) ? Collections.emptySet() : Stream.of(scope.split("\\s+")).collect(Collectors.toSet());
        }
    }
}
