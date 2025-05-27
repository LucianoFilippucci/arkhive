package it.arkhive.arkhive.Helper.POJO;

import it.arkhive.arkhive.Entity.UserEntity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserPojo {
    private String username;
    private String bio;
    private String profilePic;

    public UserPojo fromEntityToPojo(UserEntity userEntity) {
        this.username = userEntity.getUsername();
        this.bio = userEntity.getBio();
        this.profilePic = userEntity.getProfilePic();
        return this;
    }
}
