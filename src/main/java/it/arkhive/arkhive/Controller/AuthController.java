package it.arkhive.arkhive.Controller;

import it.arkhive.arkhive.Entity.UserEntity;
import it.arkhive.arkhive.Helper.DTO.User;
import it.arkhive.arkhive.Helper.Exceptions.LoginRequiredException;
import it.arkhive.arkhive.Helper.Exceptions.UserAlreadyExistsException;
import it.arkhive.arkhive.Helper.Exceptions.UserNotExistsException;
import it.arkhive.arkhive.Helper.Exceptions.UserSessionNotFoundException;
import it.arkhive.arkhive.Helper.POJO.HttpResponse;
import it.arkhive.arkhive.Helper.POJO.LoginResponse;
import it.arkhive.arkhive.Repository.UserRepository;
import it.arkhive.arkhive.Security.Authentication.JwtUtil;
import it.arkhive.arkhive.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/user/auth")
public class AuthController {

    @Autowired
    UserService userService;


    @PostMapping("/signing")
    public ResponseEntity<HttpResponse<LoginResponse>> authenticateUser(@RequestBody User user) {
        int statusCode = HttpStatus.OK.value();
        String message = "";
        LoginResponse loginResponse = null;

        try {
            loginResponse = this.userService.performLogin(user.getUsername(), user.getPassword());
            message = "login.";
        } catch (UserNotExistsException e) {
            message = "User not exists.";
            statusCode = HttpStatus.BAD_REQUEST.value();
        }

        return ResponseEntity.ok(
                HttpResponse.<LoginResponse>builder()
                        .message(message)
                        .timestamp(LocalDateTime.now())
                        .statusCode(statusCode)
                        .data(loginResponse)
                        .build()
        );
    }

    @PostMapping("/signup")
    public ResponseEntity<HttpResponse<String>> registerUser(@RequestBody User user) {
        int statusCode = HttpStatus.CREATED.value();
        String message = "";
        String data = "";
        try {
            UserEntity entity = this.userService.newUser(user);
            data = entity.getId().toString();
            message = "User successfully registered";
        } catch (UserAlreadyExistsException e) {
            statusCode = HttpStatus.CONFLICT.value();
            message = "User already exists";
        }

        return ResponseEntity.ok(
                HttpResponse.<String>builder()
                        .timestamp(LocalDateTime.now())
                        .statusCode(statusCode)
                        .message(message)
                        .data(data)
                        .build()
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<HttpResponse<LoginResponse>> refreshToken(@RequestBody String refreshToken) {
        int statusCode = HttpStatus.OK.value();
        String message = "";
        LoginResponse loginResponse = null;

        try {
            loginResponse = this.userService.refreshToken(refreshToken);
            message = "refresh token.";
        } catch (UserNotExistsException e) {
            message = "User not exists.";
            statusCode = HttpStatus.BAD_REQUEST.value();
        } catch (LoginRequiredException | UserSessionNotFoundException e) {
            message = "Login required.";
            statusCode = HttpStatus.UNAUTHORIZED.value();
            System.out.println(e);
        }

        return ResponseEntity.ok(
                HttpResponse.<LoginResponse>builder()
                        .message(message)
                        .timestamp(LocalDateTime.now())
                        .statusCode(statusCode)
                        .data(loginResponse)
                        .build()
        );

    }
}
