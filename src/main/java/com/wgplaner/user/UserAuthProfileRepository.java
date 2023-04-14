package com.wgplaner.user;

import org.springframework.data.repository.CrudRepository;

public interface UserAuthProfileRepository extends CrudRepository<UserAuthProfile, Long> {
    UserAuthProfile findByUsername(String username);
}
