package com.example;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class CustomContextAttributesMapper implements Function<OAuth2AuthorizeRequest, Map<String, Object>> {

    public static final String REQUEST_ATTRIBUTE_NAME = OAuth2AuthorizationContext.class.getName()
            .concat(".REQUEST");

    @Override
    public Map<String, Object> apply(OAuth2AuthorizeRequest authorizeRequest) {
        Map<String, Object> contextAttributes = new HashMap<>();
        HttpServletRequest servletRequest = getHttpServletRequestOrDefault(authorizeRequest.getAttributes());
        contextAttributes.put(REQUEST_ATTRIBUTE_NAME, servletRequest);
        String scope = servletRequest.getParameter(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope)) {
            contextAttributes.put(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME,
                    StringUtils.delimitedListToStringArray(scope, " "));
        }
        return contextAttributes;
    }

    private static HttpServletRequest getHttpServletRequestOrDefault(Map<String, Object> attributes) {
        HttpServletRequest servletRequest = (HttpServletRequest) attributes.get(HttpServletRequest.class.getName());
        if (servletRequest == null) {
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            if (requestAttributes instanceof ServletRequestAttributes) {
                servletRequest = ((ServletRequestAttributes) requestAttributes).getRequest();
            }
        }
        return servletRequest;
    }

}
