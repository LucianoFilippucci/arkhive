package it.arkhive.arkhive.Helper.POJO;

import lombok.Getter;
import lombok.Setter;

import java.time.OffsetDateTime;

@Getter
@Setter
public class LoginResponse {
    private String token;
    private String refreshToken;
}
