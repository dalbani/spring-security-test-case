package com.example;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.function.Function;

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
    public ApplicationRunner runner(OAuth2AuthorizedClientManager oauth2AuthorizedClientManager) {
        return args -> {
            if (oauth2AuthorizedClientManager instanceof DefaultOAuth2AuthorizedClientManager defaultOAuth2AuthorizedClientManager) {
                defaultOAuth2AuthorizedClientManager.setContextAttributesMapper(new CustomContextAttributesMapper());
            }
        };
    }

    // @Bean
    public OAuth2AuthorizedClientProvider tokenExchangeOAuth2AuthorizedClientProvider() {
        TokenExchangeGrantRequestEntityConverter requestEntityConverter = new TokenExchangeGrantRequestEntityConverter();
        requestEntityConverter.addParametersConverter(grantRequest -> {
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.AUDIENCE, grantRequest.getClientRegistration().getRegistrationId());
            return parameters;
        });

        DefaultTokenExchangeTokenResponseClient tokenResponseClient = new DefaultTokenExchangeTokenResponseClient();
        tokenResponseClient.setRequestEntityConverter(requestEntityConverter);

        TokenExchangeOAuth2AuthorizedClientProvider authorizedClientProvider = new TokenExchangeOAuth2AuthorizedClientProvider();

        authorizedClientProvider.setAccessTokenResponseClient(tokenResponseClient);
        authorizedClientProvider.setSubjectTokenResolver(context -> {
            if (context.getPrincipal() instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
                HttpServletRequest httpServletRequest = context.getAttribute(CustomContextAttributesMapper.REQUEST_ATTRIBUTE_NAME);
                if (httpServletRequest == null) {
                    return null;
                }
                OAuth2AuthorizedClient oauth2AuthorizedClient = authorizedClientRepository().loadAuthorizedClient(
                        oauth2AuthenticationToken.getAuthorizedClientRegistrationId(),
                        context.getPrincipal(), httpServletRequest);
                return oauth2AuthorizedClient.getAccessToken();
            }
            return null;
        });

        return authorizedClientProvider;
    }

    @Bean
    public OAuth2AuthorizedClientProvider alternateTokenExchangeOAuth2AuthorizedClientProvider(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        // This OAuth2AuthorizedClientManager is used for resolving the current
        // user's access token.
        OAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);
        Function<OAuth2AuthorizationContext, OAuth2Token> subjectResolver = (context) -> {
            if (context.getPrincipal() instanceof OAuth2AuthenticationToken oauthAuthenticationToken) {
                // Get the current user's client registration id
                String clientRegistrationId = oauthAuthenticationToken.getAuthorizedClientRegistrationId();

                OAuth2AuthorizeRequest authorizeRequest =
                        OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
                                .principal(context.getPrincipal())
                                .build();
                OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
                Assert.notNull(authorizedClient, "authorizedClient cannot be null");

                return authorizedClient.getAccessToken();
            }

            return null; // This should probably throw an exception
        };

        TokenExchangeOAuth2AuthorizedClientProvider authorizedClientProvider =
                new TokenExchangeOAuth2AuthorizedClientProvider();
        authorizedClientProvider.setSubjectTokenResolver(subjectResolver);

        return authorizedClientProvider;
    }

    @Bean
    public WebClient httpBinWebClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2FilterFunction =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        oauth2FilterFunction.setDefaultOAuth2AuthorizedClient(true);
        oauth2FilterFunction.setDefaultClientRegistrationId("http-bin");
        return WebClient.builder()
                .baseUrl("https://httpbin.org/get")
                .apply(oauth2FilterFunction.oauth2Configuration())
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
