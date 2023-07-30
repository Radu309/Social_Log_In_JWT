package projectJWT.project.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import projectJWT.project.requestBody.AuthenticationRequest;
import projectJWT.project.requestBody.AuthenticationResponse;
import projectJWT.project.service.AuthenticationService;
import projectJWT.project.requestBody.RegisterRequest;

import java.io.IOException;


@RestController
//@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;
    @PostMapping("/api/v1/auth/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request){
        return ResponseEntity.ok(service.register(request));
    }
    @PostMapping("/api/v1/auth/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request   ){
        return ResponseEntity.ok(service.authenticate(request));
    }
    @PostMapping("/api/v1/auth/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }
    @GetMapping("/api/v1/check-token")
    public ResponseEntity<String> checkToken(){
        return ResponseEntity.ok("Good Token");
    }
    @GetMapping("/api/v1/demo")
    public ResponseEntity<String> sayHello1(){
        return ResponseEntity.ok("Hello from secured endpoint");
    }
    @GetMapping("/api/v1/auth/demo")
    public ResponseEntity<String> sayHello2(){
        return ResponseEntity.ok("Hello from secured endpoint");
    }
    @GetMapping("/api/v1/auth/fail")
    public ResponseEntity<String> sayHello3(){
        return ResponseEntity.ok("Hello from failed secured endpoint");
    }

}
