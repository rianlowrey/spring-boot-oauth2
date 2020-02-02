package com.example.oauth.controller;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@FrameworkEndpoint
public class IntrospectController {

    @Autowired
    private TokenStore tokenStore;

    @PostMapping("/introspect")
    @ResponseBody
    public Map<String, Object> introspect(@RequestParam("token") final String token) {
        OAuth2AccessToken oAuth2AccessToken = this.tokenStore.readAccessToken(token);

        Map<String, Object> map = new HashMap<>();
        if (null == oAuth2AccessToken || oAuth2AccessToken.isExpired()) {
            map.put("active", false);
            return map;
        }

        OAuth2Authentication auth2Authentication = this.tokenStore.readAuthentication(token);

        map.put("active", true);
        map.put("exp", oAuth2AccessToken.getExpiration().getTime());
        map.put("scope", String.join(" ", oAuth2AccessToken.getScope()));
        map.put("sub", auth2Authentication.getName());

        return map;
    }
}
