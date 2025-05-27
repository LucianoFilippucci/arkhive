package it.arkhive.arkhive.Entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.context.annotation.Lazy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Setter
@Getter
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users", schema = "public")
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, unique = true)
    private Long id;

    @Basic(optional = false)
    @Column(name = "username", nullable = false, unique = true, length = 255)
    private String username;


    @Basic(optional = false)
    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;


    @Basic(optional = false)
    @Column(name = "password", nullable = false, unique = true, length = 255)
    private String password;

    @Basic
    @Column(name = "provider", length = 255)
    private String provider;

    @Basic
    @Column(name = "provider_id", length = 255)
    private String providerId;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<UserRolesEntity> roles = new HashSet<>();

    @OneToMany(mappedBy = "user")
    private List<UserSessionEntity> sessions;

    @OneToMany(mappedBy = "user")
    private List<UserPasswordResetEntity> passwordResets;

}
