package it.arkhive.arkhive.Helper.POJO;

import lombok.*;

@Getter
@Setter
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class AuthenticationResponse {

    private String token;
    private String refreshToken;
    private int expiresIn;
    private Long sessionId;
}
