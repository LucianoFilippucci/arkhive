package it.arkhive.arkhive.Repository;

import it.arkhive.arkhive.Entity.UserSessionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSessionEntity, Long> {
    Optional<UserSessionEntity> findByRefreshToken(String token);
    UserSessionEntity findByToken(String token);
    Optional<UserSessionEntity> findBySessionId(Long id);
}
