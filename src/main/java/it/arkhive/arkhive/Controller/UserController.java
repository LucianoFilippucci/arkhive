package it.arkhive.arkhive.Controller;

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
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserService userService;


    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/test")
    public String testPublic() {
        return "public content";
    }

    @GetMapping("/test/private")
    public String testPrivate() {
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

}
