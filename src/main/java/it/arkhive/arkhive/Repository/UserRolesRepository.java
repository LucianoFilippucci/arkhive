package it.arkhive.arkhive.Repository;

import it.arkhive.arkhive.Entity.UserRolesEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRolesRepository extends JpaRepository<UserRolesEntity, Long> {
}
