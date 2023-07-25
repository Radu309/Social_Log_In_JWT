package projectJWT.project.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import projectJWT.project.model.User;
import projectJWT.project.repository.UserRepository;
import projectJWT.project.service.AuthenticationService;

import java.io.IOException;
import java.util.Collections;
import java.util.function.Function;
import java.util.stream.Collectors;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration{
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final UserRepository userRepository;
    @Autowired
    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthFilter,
                                 AuthenticationProvider authenticationProvider,
                                 UserRepository userRepository) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authenticationProvider = authenticationProvider;
        this.userRepository= userRepository;
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
                .authenticationProvider(authenticationProvider)
                // this filter will process JWT-based authentication for incoming requests.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .oauth2Login()
                    .successHandler((request, response, authentication) -> {
//                        System.out.println("AuthenticationSuccessHandler invoked");
//                        System.out.println("Authentication name: " + authentication.getName());
//                        System.out.println(authentication.getDetails());
//                        System.out.println(authentication.getCredentials());
                        DefaultOidcUser defaultUser = (DefaultOidcUser) authentication.getPrincipal();
//                        System.out.println(defaultUser.getEmail());
//                        System.out.println(defaultUser.getUserInfo());
//                        System.out.println(defaultUser);
//                        System.out.println(request);

                                (response.getHeaderNames())
                                .stream()
                                        .forEach(System.out::println);

                        System.out.println(response.getHeader("Set-Cookie"));
                        System.out.println(response.getOutputStream());
                        System.out.println(response.getHeaderNames());
                        response.setHeader("Auth","123");
//                        System.out.println(SecurityContextHolder.getContext().getAuthentication());
//                        System.out.println(SecurityContextHolder.getContext());
//                        CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
//                        userService.processOAuthPostLogin(oauthUser.getEmail());
                        String userEmail = defaultUser.getEmail();
                        User user = userRepository.findByEmail(userEmail)
                                .orElseThrow();
                        System.out.println(user);

                        if(userRepository.findByEmail(userEmail).isPresent()) {
                            System.out.println("GAAAAAAAAAAAAAAAAAAAAAAASIT");


                        }
//                        response.sendRedirect("/api/v1/auth/demo");
                    });

        return http.build();
    }
}
