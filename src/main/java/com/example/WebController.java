package com.example;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestClient;

@Controller
public class WebController {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebController.class);

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    private final RestClient httpBinRestClient;

    public WebController(OAuth2AuthorizedClientRepository authorizedClientRepository,
                         RestClient httpBinRestClient) {
        this.authorizedClientRepository = authorizedClientRepository;
        this.httpBinRestClient = httpBinRestClient;
    }

    @RequestMapping("/")
    public String index(OAuth2AuthenticationToken oauth2AuthenticationToken,
                        HttpServletRequest httpServletRequest,
                        Model model) {
        if (oauth2AuthenticationToken != null) {
            OidcUser oidcUser = (OidcUser) oauth2AuthenticationToken.getPrincipal();
            model.addAttribute("oidcIdToken", oidcUser.getIdToken());
            model.addAttribute("oidcAccessToken", getAccessToken(oauth2AuthenticationToken, httpServletRequest));

            ResponseEntity<String> responseEntity = httpBinRestClient
                    .get()
                    .uri("/headers")
                    .retrieve()
                    .toEntity(String.class);
            model.addAttribute("httpBinResponse", responseEntity.getBody());
        }

        return "index";
    }

    private OAuth2AccessToken getAccessToken(OAuth2AuthenticationToken oauth2AuthenticationToken,
                                             HttpServletRequest httpServletRequest) {
        OAuth2AuthorizedClient oauth2AuthorizedClient = authorizedClientRepository.loadAuthorizedClient(
                oauth2AuthenticationToken.getAuthorizedClientRegistrationId(),
                oauth2AuthenticationToken, httpServletRequest);
        return oauth2AuthorizedClient.getAccessToken();
    }

}
