package it.arkhive.arkhive.Service;

import it.arkhive.arkhive.Entity.UserEntity;
import it.arkhive.arkhive.Entity.UserPasswordResetEntity;
import it.arkhive.arkhive.Entity.UserSessionEntity;
import it.arkhive.arkhive.Helper.DTO.User;
import it.arkhive.arkhive.Helper.Exceptions.*;
import it.arkhive.arkhive.Helper.POJO.LoginResponse;
import it.arkhive.arkhive.Helper.POJO.UserPojo;
import it.arkhive.arkhive.Helper.SHAHASH;
import it.arkhive.arkhive.Repository.UserPasswordResetRepository;
import it.arkhive.arkhive.Repository.UserRepository;
import it.arkhive.arkhive.Repository.UserSessionRepository;
import it.arkhive.arkhive.Security.Authentication.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    @Value("${arkhive.password-reset.expiration}")
    private Long passwordResetTokenExpiration;

    @Value("${arkhive.password-reset.reset-endpoint}")
    private String passwordResetResetEndpoint;

    @Value("${arkhive.s3.bucket}")
    private String bucket;

    @Value("${arkhive.s3.uri}")
    private String s3Uri;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtils;
    private final UserSessionRepository userSessionRepository;
    private final UserPasswordResetRepository passwordResetRepository;
    private final MailerService mailerService;
    private final S3Client s3Client;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtUtil jwtUtils, UserSessionRepository userSessionRepository, UserPasswordResetRepository passwordResetRepository, MailerService mailerService, S3Client s3Client) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.userSessionRepository = userSessionRepository;
        this.passwordResetRepository = passwordResetRepository;
        this.mailerService = mailerService;
        this.s3Client = s3Client;
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

        UserSessionEntity userSession = new UserSessionEntity();
        userSession.setUser(user);
        userSession.setToken("");
        userSession.setRefreshToken("");
        userSession.setLastLoginAt(OffsetDateTime.now());
        userSession.setUpdatedAt(OffsetDateTime.now());
        userSession.setLocation("");
        userSession.setDeviceName("");
        userSession.setRevoked(false);
        UserSessionEntity tmp2 = this.userSessionRepository.save(userSession);


        String token = jwtUtils.generateToken(user, tmp2.getSessionId());


        String refreshToken = jwtUtils.generateRefreshToken(user, tmp2.getSessionId());
        String hashedToken = SHAHASH.hash(refreshToken); // SHA-256 hashing to decrease the string length <= 72 bytes
        String encoded = passwordEncoder.encode(hashedToken);

        tmp2.setToken(token);
        tmp2.setRefreshToken(encoded);
        tmp2.setUpdatedAt(OffsetDateTime.now());
        UserSessionEntity tmp3 = this.userSessionRepository.save(tmp2);

        loginResponse.setToken(token);
        loginResponse.setRefreshToken(refreshToken);



        return loginResponse;
    }

    @Transactional
    public LoginResponse refreshToken(String refreshToken) throws UserNotExistsException, LoginRequiredException, UserSessionNotFoundException {
        if(jwtUtils.validateRefreshToken(refreshToken)) {
            Optional<UserEntity> tmp = this.userRepository.findByUsername(jwtUtils.getRefreshTokenSubject(refreshToken));
            if(tmp.isEmpty()) throw new UserNotExistsException("Username not found.");
            UserEntity user = tmp.get();



            String hashedToken = SHAHASH.hash(refreshToken);
            String encoded = passwordEncoder.encode(hashedToken);

            Long sessionId = jwtUtils.getRefreshTokenSessionId(refreshToken);

            Optional<UserSessionEntity> tmp2 = this.userSessionRepository.findBySessionId(sessionId);
            if(tmp2.isEmpty()) throw new UserSessionNotFoundException("Session Not Found.");
            UserSessionEntity session = tmp2.get();
            if(passwordEncoder.matches(hashedToken, session.getRefreshToken())) {
                String newRefreshToken = jwtUtils.generateRefreshToken(user, sessionId);
                String accessToken = jwtUtils.generateToken(user, sessionId);

                String newHashedToken = SHAHASH.hash(newRefreshToken);
                String newEncoded = passwordEncoder.encode(newHashedToken);
                session.setRefreshToken(newEncoded);

                session.setToken(accessToken);
                session.setUpdatedAt(OffsetDateTime.now());
                session.setLastLoginAt(OffsetDateTime.now());
                UserSessionEntity tmp3 = this.userSessionRepository.save(session);

                LoginResponse loginResponse = new LoginResponse();
                loginResponse.setToken(accessToken);
                loginResponse.setRefreshToken(newRefreshToken);
                return loginResponse;
            }
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



    @Transactional
    public void requestPasswordReset(String email) throws UserNotExistsException, EmailException {
         Optional<UserEntity> tmp = this.userRepository.findByEmail(email);
         if(tmp.isEmpty()) throw new UserNotExistsException("User not found.");
         UserEntity user = tmp.get();

         // Find all the request made on that email, invalidate the oldest if isUsed = false and make a new one
        List<UserPasswordResetEntity> oldFalseRequests = this.passwordResetRepository.findAllByUser(user);
        oldFalseRequests.forEach(request -> {
            if(!request.isUsed()) {
                request.setUsed(true);
            }
        });
        this.passwordResetRepository.saveAll(oldFalseRequests);

        UserPasswordResetEntity passwordReset = new UserPasswordResetEntity();
        passwordReset.setToken("");
        passwordReset.setUsed(false);

        passwordReset.setExpiresAt(OffsetDateTime.now().plus(Duration.ofMillis(this.passwordResetTokenExpiration)));
        passwordReset.setCreatedAt(OffsetDateTime.now());
        passwordReset.setUser(user);

        UserPasswordResetEntity newEntity = this.passwordResetRepository.save(passwordReset);
        String token = jwtUtils.generatePasswordResetToken(user, newEntity.getId());
        String hashedToken = SHAHASH.hash(token);
        String encoded = passwordEncoder.encode(hashedToken);
        newEntity.setToken(encoded);



        String resetLink = this.passwordResetResetEndpoint + token;
        try {
            this.mailerService.sendMail("Password Reset", "", user.getEmail(), user.getUsername(), resetLink);
        } catch (EmailException e) {
            System.out.println("Error sending email.");
            throw new EmailException("Error sending email.");
        }

        this.passwordResetRepository.save(passwordReset);
    }

    @Transactional
    public boolean resetPassword(String token, String newPassword) throws InvalidTokenException {

        Optional<UserPasswordResetEntity> tmp = this.passwordResetRepository.findByUserIdAndUsedIsFalse(this.jwtUtils.getUserIdFromResetToken(token));
        if(tmp.isEmpty()) throw new InvalidTokenException("Invalid Token");
        UserPasswordResetEntity passwordReset = tmp.get();

        if(passwordEncoder.matches(SHAHASH.hash(token), passwordReset.getToken())) {
            try {
                if(this.jwtUtils.validatePasswordResetToken(token) && !passwordReset.isUsed()) {

                    String encodedPassword = passwordEncoder.encode(newPassword);
                    passwordReset.getUser().setPassword(encodedPassword);
                    passwordReset.setUsed(true);
                    this.passwordResetRepository.save(passwordReset);

                    this.userRepository.save(passwordReset.getUser());
                    return true;
                }
            } catch (Exception e) {
                return false;
            }
        } else {
            throw new InvalidTokenException("Invalid Token");
        }
        return false;
    }

    @Transactional
    public String  uploadProfilePic(MultipartFile file, String token) throws IOException, UserNotExistsException{

        Optional<UserEntity> tmp = this.userRepository.findById(this.jwtUtils.getUserIdFromToken(token));
        if(tmp.isEmpty()) throw new UserNotExistsException("User not found.");
        UserEntity user = tmp.get();


        String originalFilename = file.getOriginalFilename();
        String extension = originalFilename != null && originalFilename.contains(".") ? originalFilename.substring(originalFilename.lastIndexOf(".")) : "";
        String uuid = UUID.randomUUID().toString();
        String key = "public/users/" + user.getId() + "/" + uuid + extension;

        user.setProfilePic(uuid);

        PutObjectRequest putRequest = PutObjectRequest.builder()
                .bucket(bucket)
                .key(key)
                .contentType(file.getContentType())
                .build();
        s3Client.putObject(putRequest, RequestBody.fromBytes(file.getBytes()));

        this.userRepository.save(user);
        return s3Uri + "/" + bucket + "/" + key;

    }

    @Transactional
    public boolean updateBio(String token, String bio) throws UserNotExistsException, IllegalArgumentException {
        Optional<UserEntity> tmp = this.userRepository.findById(this.jwtUtils.getUserIdFromToken(token));
        if(tmp.isEmpty()) throw new UserNotExistsException("User not found.");
        UserEntity user = tmp.get();

        if(bio.length() > 200) throw new IllegalArgumentException("bio length exceeds 200");

        user.setBio(bio);
        this.userRepository.save(user);
        return true;
    }

    @Transactional
    public String getBio(String token) throws UserNotExistsException {
        Optional<UserEntity> tmp = this.userRepository.findById(this.jwtUtils.getUserIdFromToken(token));
        if(tmp.isEmpty()) throw new UserNotExistsException("User not found.");
        UserEntity user = tmp.get();
        return user.getBio();
    }

    @Transactional
    public UserPojo getUser(Long id) throws UserNotExistsException, UserProfileNotPublicException {
        Optional<UserEntity> tmp = this.userRepository.findById(id);
        if(tmp.isEmpty()) throw new UserNotExistsException("User not found.");
        UserEntity user = tmp.get();
        if(user.isPublicProfile())
            return new UserPojo().fromEntityToPojo(user);
        throw new UserProfileNotPublicException("User not public");
    }
}
