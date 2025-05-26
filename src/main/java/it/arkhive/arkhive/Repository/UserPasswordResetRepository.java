package it.arkhive.arkhive.Repository;

import it.arkhive.arkhive.Entity.UserEntity;
import it.arkhive.arkhive.Entity.UserPasswordResetEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserPasswordResetRepository extends JpaRepository<UserPasswordResetEntity, Long> {
    Optional<UserPasswordResetEntity> findByToken(String token);
     List<UserPasswordResetEntity> findAllByUser(UserEntity user);
    Optional<UserPasswordResetEntity> findByUserIdAndUsedIsFalse(Long userId);
}
