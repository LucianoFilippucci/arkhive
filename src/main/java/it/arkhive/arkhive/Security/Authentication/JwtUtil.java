package it.arkhive.arkhive.Security.Authentication;

import io.jsonwebtoken.*;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import it.arkhive.arkhive.Entity.UserEntity;
import it.arkhive.arkhive.Helper.DTO.User;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    @Value("${arkhive.auth.secret}")
    private String jwtSecret;

    @Value("${arkhive.auth.expiration}")
    private int jwtExpirationMs;

    @Value("${arkhive.auth.refresh-token-expiration}")
    private long jwtRefreshTokenExpiration;
    @Value("${arkhive.auth.refresh-token-secret}")
    private String jwtRefreshTokenSecret;

    private SecretKey accessKey;
    private SecretKey refreshKey;
    @PostConstruct
    public void init() {
        this.accessKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        this.refreshKey = Keys.hmacShaKeyFor(jwtRefreshTokenSecret.getBytes(StandardCharsets.UTF_8));
    }

    // Generate JWT Token
    public String generateToken(UserEntity user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .claim("email", user.getEmail())
                .claim("id", user.getId())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(accessKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // Get Username from JWT Token
    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(accessKey).build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // Validate JWT Token
    public boolean validateJwtToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(accessKey).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException e) {
            System.out.println("Invalid JWT Signature: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT Token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("JWT token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("JWT claims string is empty: " + e.getMessage());
        }
        return false;
    }

    public String getRefreshTokenClaim(String token, String claim) {
        return Jwts.parserBuilder()
                .setSigningKey(refreshKey).build()
                .parseClaimsJws(token)
                .getBody()
                .get(claim, String.class);
    }

    public String getRefreshTokenSubject(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(refreshKey).build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // Generate RefreshToken
    public String generateRefreshToken(UserEntity user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtRefreshTokenExpiration))
                .claim("email", user.getEmail())
                .claim("id", user.getId())
                .signWith(refreshKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateRefreshToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(refreshKey).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException e) {
            System.out.println("Invalid Refresh Token Signature: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.out.println("Invalid Refresh Token: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            System.out.println("Refresh token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.out.println("Refresh token is unsupported: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println("Refresh claims string is empty: " + e.getMessage());
        }
        return false;
    }


}
