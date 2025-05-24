package it.arkhive.arkhive.Helper.DTO;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class User {
    private String username;
    private String password;
    private String email;
    private Long userId;
}
