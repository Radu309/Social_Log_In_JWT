package projectJWT.project.config;

import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import projectJWT.project.model.User;
import projectJWT.project.model.UserRole;
import projectJWT.project.repository.TokenRepository;
import projectJWT.project.repository.UserRepository;
import projectJWT.project.service.AuthenticationService;
import projectJWT.project.service.JwtService;

import java.util.Arrays;
import java.util.Date;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final JwtService jwtService;
    @Autowired
    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthFilter,
                                 AuthenticationProvider authenticationProvider,
                                 JwtService jwtService
    ) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authenticationProvider = authenticationProvider;
        this.jwtService = jwtService;
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // this line configures Cross-Origin Resource Sharing (CORS) and disables Cross-Site Request Forgery (CSRF) protection. It allows requests from different origins and disables CSRF protection since the application is using JWT-based authentication, which is stateless and does not rely on CSRF tokens.
                // You are using another token mechanism. You want to simplify interactions between a client and the server(so...disable csrf).
                .csrf().disable()
                // initiates the configuration of authorization rules for incoming requests.
                .authorizeHttpRequests()
                // give all permissions for the next endPont
                .requestMatchers("/api/v1/auth/**", "/api/v1/check-token").permitAll()
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
                    DefaultOidcUser defaultUser = (DefaultOidcUser) authentication.getPrincipal();
                    String userEmail = defaultUser.getEmail();
                    User user = User.builder().email(userEmail).userRole(UserRole.USER).build();
                    String token = jwtService.generateToken(user);
                    String refreshToken = jwtService.generateRefreshToken(user);
                    jwtService.saveUserToken(user,token,refreshToken);

                    Date currentDate = new Date();
                    Cookie accessTokenCookie = new Cookie("token",token);
                    accessTokenCookie.setSecure(true);
                    accessTokenCookie.setHttpOnly(true);
                    int dateCookie = (int)(jwtService.extractExpiration(token).getTime() - currentDate.getTime());
                    accessTokenCookie.setMaxAge(dateCookie);
                    accessTokenCookie.setPath("/");

                    response.addCookie(accessTokenCookie);
                    response.sendRedirect("/api/v1/auth/demo");
                });
        return http.build();
    }
}