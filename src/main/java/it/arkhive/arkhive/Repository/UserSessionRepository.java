package it.arkhive.arkhive.Repository;

import it.arkhive.arkhive.Entity.UserSessionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSessionEntity, Long> {
    UserSessionEntity findByRefreshToken(String token);
    UserSessionEntity findByToken(String token);
}
