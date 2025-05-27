package it.arkhive.arkhive.Controller;

import it.arkhive.arkhive.Helper.Exceptions.UserProfileNotPublicException;
import it.arkhive.arkhive.Helper.POJO.UserPojo;
import it.arkhive.arkhive.Security.Authentication.JwtUtil;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import it.arkhive.arkhive.Entity.UserEntity;
import it.arkhive.arkhive.Helper.DTO.User;
import it.arkhive.arkhive.Helper.Exceptions.EmailException;
import it.arkhive.arkhive.Helper.Exceptions.UserNotExistsException;
import it.arkhive.arkhive.Helper.POJO.HttpResponse;
import it.arkhive.arkhive.Service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public UserController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/test")
    public String testPublic() {
        return "public content";
    }

    @GetMapping("/test/private")
    public String testPrivate(@AuthenticationPrincipal String jwt) {
        System.out.println(jwtUtil.getUserIdFromToken(jwt));
        return "User Content.";
    }

    @PostMapping("/password/reset/request")
    public ResponseEntity<HttpResponse<Boolean>> requestPasswordReset(@RequestBody String email) {
        System.out.println("Email: " + email);
        String message = "";
        int status = HttpStatus.OK.value();
        boolean success = true;

        try {
            this.userService.requestPasswordReset(email);
        } catch (UserNotExistsException e){
            success = false;
            message = "User Not Found.";
        } catch (EmailException e) {
            success = false;
            message = "Email Error.";
        }

        return ResponseEntity.ok(
                HttpResponse.<Boolean>builder()
                        .timestamp(LocalDateTime.now())
                        .message(message)
                        .statusCode(status)
                        .data(success)
                        .build()
        );
    }

    @PostMapping("/password/reset")
    public ResponseEntity<HttpResponse<Boolean>> requestPasswordReset(@RequestParam String token, @RequestBody String newPassword) {
        String message = "";
        int status = HttpStatus.OK.value();
        boolean success = true;

        try {
            success = this.userService.resetPassword(token, newPassword);
            message = "Password Changed.";
        } catch (UserNotExistsException e){
            success = false;
            message = "User Not Found.";
            status = HttpStatus.NOT_FOUND.value();
        } catch (EmailException e) {
            success = false;
            message = "Email Error.";
            status = HttpStatus.BAD_REQUEST.value();
        }

        return ResponseEntity.ok(
                HttpResponse.<Boolean>builder()
                        .timestamp(LocalDateTime.now())
                        .statusCode(status)
                        .message(message)
                        .data(success)
                        .build()
        );
    }


    @PostMapping("/upload/profile-pic")
    public ResponseEntity<HttpResponse<String>> uploadProfilePic(@RequestParam("file") MultipartFile file, @AuthenticationPrincipal String jwt) {

        String message = "";
        int status = HttpStatus.OK.value();
        String picUrl = "";

        try {
            picUrl = this.userService.uploadProfilePic(file, jwt);
        } catch (IOException e) {
            System.out.println("S3 Error: " + e.getMessage());
            message = "Error: " + e.getMessage();
            status = HttpStatus.INTERNAL_SERVER_ERROR.value();
        }

        return ResponseEntity.ok(
                HttpResponse.<String>builder()
                        .timestamp(LocalDateTime.now())
                        .statusCode(status)
                        .message(message)
                        .data(picUrl)
                        .build()
        );

    }

    @PostMapping("/bio")
    public ResponseEntity<HttpResponse<Boolean>> uploadBio(@AuthenticationPrincipal String jwt, @RequestBody String bio) {
        String message = "";
        int status = HttpStatus.OK.value();
        boolean success = true;
        int errorCode = -1;

        try {
            this.userService.updateBio(jwt, bio);
            message = "Bio Updated.";
        } catch (UserNotExistsException e){
            success = false;
            message = "User Not Found.";
            status = HttpStatus.NOT_FOUND.value();
            errorCode = 404;
        } catch(IllegalArgumentException e) {
            success = false;
            message = "Bio length exceeds 200 characters.";
            status = HttpStatus.BAD_REQUEST.value();
            errorCode = 400;
        }

        return ResponseEntity.ok(
                HttpResponse.<Boolean>builder()
                        .timestamp(LocalDateTime.now())
                        .message(message)
                        .statusCode(status)
                        .errorCode(errorCode)
                        .data(success)
                        .build()
        );

    }

    @GetMapping("/bio")
    public ResponseEntity<HttpResponse<String>> getBio(@AuthenticationPrincipal String jwt) {
        String message = "";
        int status = HttpStatus.OK.value();
        String bio = "";
        int errorCode = -1;

        try {
            bio = this.userService.getBio(jwt);
        } catch (UserNotExistsException e) {
            message = "User Not Found.";
            status = HttpStatus.NOT_FOUND.value();
            errorCode = 404;
        }

        return ResponseEntity.ok(
                HttpResponse.<String>builder()
                        .timestamp(LocalDateTime.now())
                        .message(message)
                        .statusCode(status)
                        .errorCode(errorCode)
                        .data(bio)
                        .build()
        );
    }

    @GetMapping("/{user-id}")
    public ResponseEntity<HttpResponse<UserPojo>> getUser(@PathVariable("user-id") Long userId) {
        String message = "";
        int status = HttpStatus.OK.value();
        UserPojo userPojo = null;
        int errorCode = -1;
        
        try {
            userPojo = this.userService.getUser(userId);
        } catch (UserNotExistsException e) {
            message = "User Not Found.";
            status = HttpStatus.NOT_FOUND.value();
            errorCode = 404;
        } catch (UserProfileNotPublicException e) {
            message = "User Profile Not Public.";
            status = HttpStatus.UNAUTHORIZED.value();
            errorCode = 401;
        }
        
        return ResponseEntity.ok(
                HttpResponse.<UserPojo>builder()
                        .timestamp(LocalDateTime.now())
                        .statusCode(status)
                        .message(message)
                        .errorCode(errorCode)
                        .data(userPojo)
                        .build()
        );
    }
}
