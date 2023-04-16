package com.wgplaner.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserAuthProfileUserDetailsService implements UserDetailsService {
    private final UserAuthProfileRepository userRepository;

    public UserAuthProfileUserDetailsService(UserAuthProfileRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAuthProfile userAuthProfile = userRepository.findByUsername(username);
        if(userAuthProfile != null) {
            return userAuthProfile;
        }
        throw new UsernameNotFoundException("User " + username + "not found");
    }
}
