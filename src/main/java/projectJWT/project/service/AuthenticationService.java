package projectJWT.project.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import projectJWT.project.model.Token;
import projectJWT.project.model.TokenType;
import projectJWT.project.repository.TokenRepository;
import projectJWT.project.requestBody.AuthenticationRequest;
import projectJWT.project.requestBody.AuthenticationResponse;
import projectJWT.project.requestBody.RegisterRequest;
import projectJWT.project.model.User;
import projectJWT.project.repository.UserRepository;

import java.io.IOException;
import java.util.Objects;

@RequiredArgsConstructor
@Service
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        if(repository.findByEmail(request.getEmail()).isPresent()){
            throw new IllegalArgumentException("Email already exists");
        }
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .userRole(request.getRole())
                .build();
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken, refreshToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken, refreshToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        if(request.getHeader(HttpHeaders.AUTHORIZATION) != null) {
            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            final String refreshToken;
            final String userEmail;
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return;
            }
            refreshToken = authHeader.substring(7);
            //  CHECK IF THE REFRESH TOKEN EXISTS
            var storeRefreshToken = tokenRepository.findByRefreshToken(refreshToken);
            if (storeRefreshToken.isPresent()) {
                if (Objects.equals(storeRefreshToken.get().getRefreshToken(), refreshToken)) {
                    //  EXTRACT THE USER
                    userEmail = jwtService.extractUsername(refreshToken);
                    //  CHECK IF THE USER EXISTS
                    if (userEmail != null) {
                        var user = this.repository.findByEmail(userEmail)
                                .orElseThrow();
                        //  CHECK IF THE REFRESH TOKEN IS VALID
                        if (jwtService.isTokenValid(refreshToken, user)) {
                            //  GENERATE NEW TOKENS
                            var accessToken = jwtService.generateToken(user);
                            var newRefreshToken = jwtService.generateRefreshToken(user);
                            //  REMOVE THE AUTHORITIES FOR THE LAST TOKENS AND SAVE THE NEW TOKENS
                            revokeAllUserTokens(user);
                            saveUserToken(user, accessToken, newRefreshToken);
                            var authResponse = AuthenticationResponse.builder()
                                    .accessToken(accessToken)
                                    .refreshToken(newRefreshToken)
                                    .build();
                            new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                        } else {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid refresh token");
                        }
                    } else {
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "User not found");
                    }
                } else {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid refresh token");
                }
            } else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Refresh token not found");
            }
        }
        else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "NULL token");
        }

    }
    private void saveUserToken(User user, String jwtToken, String refreshToken){
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .refreshToken(refreshToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }
    private void revokeAllUserTokens(User user){
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if(validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }


}
