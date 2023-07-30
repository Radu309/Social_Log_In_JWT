package projectJWT.project.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final OAuth2AuthorizedClientService authorizedClientService;
    @Autowired
    public CustomAuthenticationSuccessHandler(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }
    private OAuth2AccessToken getAccessToken(OAuth2AuthenticationToken authentication) {
        if (authentication != null) {
            String clientRegistrationId = authentication.getAuthorizedClientRegistrationId();
            String userName = authentication.getName();
            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(clientRegistrationId, userName);
            if (authorizedClient != null) {
                return authorizedClient.getAccessToken();
            }
        }
        return null;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain chain,
                                        Authentication authentication)
            throws IOException, ServletException {

        AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {
        OAuth2AccessToken accessToken = getAccessToken((OAuth2AuthenticationToken) authentication);

        // Create a custom response object containing the access token and any other relevant information.
        Map<String, String> responseBody = new HashMap<>();
        String tokenExpired = Objects.requireNonNull(accessToken.getExpiresAt()).toString();
        String tokenIssued = Objects.requireNonNull(accessToken.getIssuedAt()).toString();
        responseBody.put("access_token", accessToken.getTokenValue());
        responseBody.put("token_type", accessToken.getTokenType().getValue());
        responseBody.put("Issued at = ", tokenIssued);
        responseBody.put("Expired at = ", tokenExpired);

        System.out.println(accessToken);

        // Convert the response object to JSON.
        String jsonResponse = objectMapper.writeValueAsString(responseBody);

        // Set the appropriate headers and write the response JSON to the response.
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(jsonResponse);

    }
}
