package it.arkhive.arkhive.Entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

@Getter
@Setter
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Entity
@Table(name = "user_session", schema = "public")
public class UserSessionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "session_id", nullable = false, unique = true, updatable = false)
    private Long sessionId;

    @Basic
    @Column(name = "token", nullable = false)
    private String token;

    @Basic
    @Column(name = "refresh_token", nullable = false)
    private String refreshToken;

    @Basic
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @Basic
    @Column(name = "last_login_at", nullable = false)
    private OffsetDateTime lastLoginAt;

    @Basic
    @Column(name = "device_name", nullable = false, length = 255)
    private String deviceName;

    @Basic
    @Column(name = "location", nullable = false, length = 255)
    private String location;

    @Basic
    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private UserEntity user;
}
