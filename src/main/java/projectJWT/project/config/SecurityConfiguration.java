package projectJWT.project.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration{
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthFilter,
                                 AuthenticationProvider authenticationProvider,
                                 OAuth2AuthorizedClientService authorizedClientService
                                ) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authenticationProvider = authenticationProvider;
        this.authorizedClientService = authorizedClientService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // this line configures Cross-Origin Resource Sharing (CORS) and disables Cross-Site Request Forgery (CSRF) protection. It allows requests from different origins and disables CSRF protection since the application is using JWT-based authentication, which is stateless and does not rely on CSRF tokens.
                .csrf().disable()
                // initiates the configuration of authorization rules for incoming requests.
                .authorizeHttpRequests()
                // give all permissions for the next endPont
                .requestMatchers("/api/v1/auth/**").permitAll()
                // requires authentication for any other endPoints
                .anyRequest().authenticated()
                // used for setting other configurations
                .and()
                // configuration the session management, This means that the application will not create or use HTTP session for storing user state
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                // used for setting other configurations
                .and()
                // sets the custom authentication provider to be used for authenticating users
//                .authenticationProvider(authenticationProvider)
                // this filter will process JWT-based authentication for incoming requests.
//                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                .oauth2Login();
//                    .successHandler( new CustomAuthenticationSuccessHandler(authorizedClientService));
//
//                            (request, response, authentication) -> {
//
//                        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
//                        String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
//                        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(clientRegistrationId, oauthToken.getName());
//                        String accessToken = authorizedClient.getAccessToken().getTokenValue();
//                        System.out.println(accessToken);
//
//                    });
                /*
                .authorizationEndpoint()
                .baseUri("/oauth2/authorization")
                .authorizationRequestRepository(authorizationRequestRepository())
                .and()
                .tokenEndpoint()
                .accessTokenResponseClient(accessTokenResponseClient())
                .and()
                .defaultSuccessUrl("/api/v1/auth/login-success")
                .failureUrl("/api/v1/auth/fail");

                 */

//                    .successHandler((request, response, authentication) -> {
////
////                        DefaultOidcUser defaultUser = (DefaultOidcUser) authentication.getPrincipal();
//
////                                (response.getHeaderNames())
////                                .stream()
////                                        .forEach(System.out::println);
//
////
////                        response.setHeader("Auth","123");
////                        CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
////                        userService.processOAuthPostLogin(oauthUser.getEmail());
////                        String userEmail = defaultUser.getEmail();
////                        User user = userRepository.findByEmail(userEmail)
////                                .orElseThrow();
////                        System.out.println(user);
//
////                        if(userRepository.findByEmail(userEmail).isPresent()) {
////                            System.out.println("GAAAAAAAAAAAAAAAAAAAAAAASIT");
////                        }
////                        response.sendRedirect("/api/v1/auth/demo");
//                    });
        return http.build();
    }

    /*
    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }
    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        return new DefaultAuthorizationCodeTokenResponseClient();
    }
    // additional configuration for non-Spring Boot projects
    private static final List<String> clients = Arrays.asList("google", "facebook");

    //    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = new ArrayList<>();
        for (String client : clients) {
            // Get the ClientRegistration object for the current client name
            ClientRegistration registration = getRegistration(client);

            // Check if the registration is not null before adding it to the list
            if (registration != null) {
                registrations.add(registration);
            }
        }
        return new InMemoryClientRegistrationRepository(registrations);
    }
    //    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }
    @Autowired
    private Environment env;
    private ClientRegistration getRegistration(String client) {
        String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";

        String clientId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");

        if (clientId == null) {
            return null;
        }
        String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");
        if (client.equals("google")) {
            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        }
        if (client.equals("facebook")) {
            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        }
        return null;
    }

     */

}
