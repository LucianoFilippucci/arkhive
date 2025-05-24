package it.arkhive.arkhive.Controller;

import it.arkhive.arkhive.Entity.UserEntity;
import it.arkhive.arkhive.Helper.DTO.User;
import it.arkhive.arkhive.Service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

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

}
