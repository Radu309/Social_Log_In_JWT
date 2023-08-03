package projectJWT.project.config;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import projectJWT.project.model.Token;
import projectJWT.project.model.User;
import projectJWT.project.repository.TokenRepository;
import projectJWT.project.repository.UserRepository;
import projectJWT.project.service.JwtService;

import java.io.IOException;
import java.util.Date;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final Cookie[] cookies = request.getCookies();
        String jwt = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("token".equals(cookie.getName())) {
                    jwt = cookie.getValue();
                    break;
                }
            }
        }
        System.out.println("TOKEN: " + jwt);
        if (jwt == null || jwt.isBlank() || request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }
        System.out.println("TOKEEEEEEN NOT NULL");
        Optional<Token> currentToken = tokenRepository.findByToken(jwt);
        if(currentToken.isEmpty()){
            filterChain.doFilter(request, response);
            return;
        }
        try{
            System.out.println(jwtService.extractExpiration(currentToken.get().getToken()));
            System.out.println("Refresh: " + jwtService.extractExpiration(currentToken.get().getRefreshToken()));
            User user = currentToken.get().getUser();
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                if (!jwtService.isTokenExpired(jwt)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            user.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            filterChain.doFilter(request, response);
        }catch (ExpiredJwtException ex){
            try {
                User user = currentToken.get().getUser();
                String newAccessToken = jwtService.refreshToken(currentToken.get().getRefreshToken(), user);

                if (tokenRepository.findByToken(newAccessToken).isEmpty()) {
                    System.out.println("Nu exista refreshToken");
                    return;
                }
                String newRefreshToken = tokenRepository.findByToken(newAccessToken).get().getRefreshToken();
                System.out.println(jwtService.extractExpiration(newAccessToken));
                System.out.println("Refresh: " + jwtService.extractExpiration(newRefreshToken));

                Date currentDate = new Date();
                Cookie accessTokenCookie = new Cookie("token", newAccessToken);
                accessTokenCookie.setSecure(true);
                accessTokenCookie.setHttpOnly(true);
                int dateCookie = (int) (jwtService.extractExpiration(newAccessToken).getTime() - currentDate.getTime());
                accessTokenCookie.setMaxAge(dateCookie);
                accessTokenCookie.setPath("/");
                response.addCookie(accessTokenCookie);

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        user,
                        null,
                        user.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }catch (ExpiredJwtException ex1){
                System.out.println("Refresh token expired");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                System.out.println("HERE IS 401 ERROR");
                return;
            }
            filterChain.doFilter(request, response);
        }
    }
}
