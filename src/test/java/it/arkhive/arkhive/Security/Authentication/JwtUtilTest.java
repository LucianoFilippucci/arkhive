package it.arkhive.arkhive.Security.Authentication;

import it.arkhive.arkhive.Entity.UserEntity;
import org.junit.jupiter.api.AutoClose;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
@SpringBootTest
public class JwtUtilTest {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private Environment env;

    @Test
    void printDialect() {
        String platform = env.getProperty("spring.jpa.database-platform");
        System.out.println("DIALECT IN TEST -> " + platform);
    }
    @Test
    void testGenerateToken() {
        UserEntity userEntity = getUserEntity();

        String token = jwtUtil.generateToken(userEntity, 1L);
        assertNotNull(token);
    }

    @Test
    void testValidateJwtToken() {
        UserEntity userEntity = getUserEntity();
        String token = jwtUtil.generateToken(userEntity, 1L);

        boolean value = assertDoesNotThrow(() ->
            jwtUtil.validateJwtToken(token)
        );

        assertTrue(value);

    }

    @Test
    void testGetUsernameFromToken() {
        UserEntity user = getUserEntity();
        String token = jwtUtil.generateToken(user, 1L);
        String username = jwtUtil.getUsernameFromToken(token);
        assertNotNull(username);
        assertEquals(user.getUsername(), username);
    }

    @Test
    void testGenerateRefreshToken() {
        UserEntity user = getUserEntity();
        String token = jwtUtil.generateRefreshToken(user, 1L);
        assertNotNull(token);
    }

    @Test
    void testValidateRefreshToken() {
        UserEntity user = getUserEntity();
        String token = jwtUtil.generateRefreshToken(user, 1L);
        boolean value = assertDoesNotThrow(() -> jwtUtil.validateRefreshToken(token));
        assertTrue(value);
    }

    @Test
    void testGetRefreshTokenSessionId() {
        UserEntity user = getUserEntity();
        String token = jwtUtil.generateRefreshToken(user, 1L);
        assertNotNull(token);

        assertEquals(1L, jwtUtil.getRefreshTokenSessionId(token));
    }

    @Test
    void testGetRefreshTokenSubject() {
        UserEntity user = getUserEntity();
        String token = jwtUtil.generateRefreshToken(user, 1L);
        assertNotNull(token);
        assertEquals(user.getUsername(), jwtUtil.getRefreshTokenSubject(token));
    }

    @Test
    void testGeneratePasswordResetToken() {
        UserEntity user = getUserEntity();
        String token = jwtUtil.generatePasswordResetToken(user, 1L);
        assertNotNull(token);
    }

    @Test
    void testValidatePasswordResetToken() {
        UserEntity user = getUserEntity();
        String token = jwtUtil.generatePasswordResetToken(user, 1L);
        boolean value = assertDoesNotThrow(() -> jwtUtil.validatePasswordResetToken(token));
        assertTrue(value);
    }

    @Test
    void testGetUserIdFromResetToken() {
        UserEntity user = getUserEntity();
        String token = jwtUtil.generatePasswordResetToken(user, 1L);
        assertNotNull(token);

        assertEquals(1L, jwtUtil.getUserIdFromResetToken(token));
    }


    UserEntity getUserEntity() {
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername("test");
        userEntity.setPassword("password");
        userEntity.setEmail("test@test");
        userEntity.setId(1L);

        return userEntity;
    }
}
