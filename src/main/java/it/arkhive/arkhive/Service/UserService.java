package it.arkhive.arkhive.Service;

import it.arkhive.arkhive.Entity.UserEntity;
import it.arkhive.arkhive.Entity.UserSessionEntity;
import it.arkhive.arkhive.Helper.DTO.User;
import it.arkhive.arkhive.Helper.Exceptions.LoginRequiredException;
import it.arkhive.arkhive.Helper.Exceptions.UserAlreadyExistsException;
import it.arkhive.arkhive.Helper.Exceptions.UserNotExistsException;
import it.arkhive.arkhive.Helper.POJO.LoginResponse;
import it.arkhive.arkhive.Repository.UserRepository;
import it.arkhive.arkhive.Repository.UserSessionRepository;
import it.arkhive.arkhive.Security.Authentication.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtils;
    private final UserSessionRepository userSessionRepository;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtUtil jwtUtils, UserSessionRepository userSessionRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userSessionRepository = userSessionRepository;
    }

    @Transactional
    public UserEntity newUser(User userDto) throws UserAlreadyExistsException {
        if(this.userRepository.existsByUsername(userDto.getUsername()))
            throw new UserAlreadyExistsException("Username already exists.");

        UserEntity user = new UserEntity();
        user.setEmail(userDto.getEmail());
        user.setUsername(userDto.getUsername());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));

        return this.userRepository.save(user);
    }

    @Transactional
    public LoginResponse performLogin(String username, String password) throws UserNotExistsException {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        username,
                        password
                )
        );
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        LoginResponse loginResponse = new LoginResponse();
        Optional<UserEntity> tmp = this.userRepository.findByUsername(userDetails.getUsername());
        if(tmp.isEmpty()) throw new UserNotExistsException("Username not found.");
        UserEntity user = tmp.get();
        String token = jwtUtils.generateToken(user);
        String refreshToken = jwtUtils.generateRefreshToken(user);
        loginResponse.setToken(token);
        loginResponse.setRefreshToken(refreshToken);

        UserSessionEntity userSession = new UserSessionEntity();
        userSession.setUser(user);
        userSession.setToken(token);
        userSession.setRefreshToken(refreshToken);
        userSession.setLastLoginAt(OffsetDateTime.now());
        userSession.setUpdatedAt(OffsetDateTime.now());
        userSession.setLocation("");
        userSession.setDeviceName("");
        userSession.setRevoked(false);

        UserSessionEntity tmp2 = this.userSessionRepository.save(userSession);

        return loginResponse;
    }

    @Transactional
    public LoginResponse refreshToken(String refreshToken) throws UserNotExistsException, LoginRequiredException {
        if(jwtUtils.validateRefreshToken(refreshToken)) {
            Optional<UserEntity> tmp = this.userRepository.findByUsername(jwtUtils.getRefreshTokenSubject(refreshToken));
            if(tmp.isEmpty()) throw new UserNotExistsException("Username not found.");
            UserEntity user = tmp.get();
            String accessToken = jwtUtils.generateToken(user);
            String newRefreshToken = jwtUtils.generateRefreshToken(user);

            UserSessionEntity session = this.userSessionRepository.findByRefreshToken(refreshToken);
            session.setRefreshToken(newRefreshToken);
            session.setToken(accessToken);
            session.setUpdatedAt(OffsetDateTime.now());
            session.setLastLoginAt(OffsetDateTime.now());
            UserSessionEntity tmp2 = this.userSessionRepository.save(session);



            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setToken(accessToken);
            loginResponse.setRefreshToken(newRefreshToken);
            return loginResponse;
        }
        throw new LoginRequiredException("Refresh token not valid.");
    }

    @Transactional
    public boolean invalidateSession(String token) {
        UserSessionEntity session = this.userSessionRepository.findByToken(token);
        if(session == null) return true;

        session.setRevoked(true);
        this.userSessionRepository.save(session);
        return true;
    }

}
