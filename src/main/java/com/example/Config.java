package com.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.RestClientTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class Config {

    private static final Logger LOGGER = LoggerFactory.getLogger(Config.class);

    private final ClientRegistrationRepository clientRegistrationRepository;

    public Config(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    public OAuth2AuthorizedClientProvider tokenExchangeOAuth2AuthorizedClientProvider(
            @Lazy OAuth2AuthorizedClientManager authorizedClientManager) {
        RestClientTokenExchangeTokenResponseClient tokenResponseClient = new RestClientTokenExchangeTokenResponseClient();
        tokenResponseClient.addParametersConverter(grantRequest -> {
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.AUDIENCE, grantRequest.getClientRegistration().getRegistrationId());
            return parameters;
        });

        TokenExchangeOAuth2AuthorizedClientProvider authorizedClientProvider = new TokenExchangeOAuth2AuthorizedClientProvider();

        authorizedClientProvider.setAccessTokenResponseClient(tokenResponseClient);
        authorizedClientProvider.setSubjectTokenResolver(context -> {
            if (context.getPrincipal() instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
                String clientRegistrationId = oauth2AuthenticationToken.getAuthorizedClientRegistrationId();

                OAuth2AuthorizeRequest authorizeRequest =
                        OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
                                .principal(oauth2AuthenticationToken)
                                .build();

                OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
                Assert.notNull(authorizedClient, "authorizedClient cannot be null");

                return authorizedClient.getAccessToken();
            }
            return null;
        });

        return authorizedClientProvider;
    }

    @Bean
    public RestClient httpBinRestClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        OAuth2ClientHttpRequestInterceptor requestInterceptor =
                new OAuth2ClientHttpRequestInterceptor(authorizedClientManager, request -> "http-bin");

        return RestClient.builder()
                .baseUrl("https://httpbin.org/")
                .requestInterceptor(requestInterceptor)
                .build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        .requestMatchers("/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(withDefaults())
                .logout(logout -> logout
                        .deleteCookies()
                        .logoutRequestMatcher(new OrRequestMatcher(
                                antMatcher(HttpMethod.GET, "/logout"),
                                antMatcher(HttpMethod.POST, "/logout")))
                        .logoutSuccessHandler(oidcLogoutSuccessHandler()))
                .build();
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        return oidcLogoutSuccessHandler;
    }

}
