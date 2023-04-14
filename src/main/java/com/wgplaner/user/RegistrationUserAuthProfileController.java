package com.wgplaner.user;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@RestController("/register")
@RequiredArgsConstructor
public class RegistrationUserAuthProfileController {
    private final UserAuthProfileRepository userAuthProfileRepository;
    private final PasswordEncoder passwordEncoder;
    @PostMapping(path = "/new")
    @ResponseStatus(HttpStatus.CREATED)
    public Long register(@RequestBody @Valid UserAuthProfileDto userAuthProfileDto) {
        if( userAuthProfileRepository.findByUsername( userAuthProfileDto.username()) != null ) {
            throw new IllegalArgumentException("New user registration failed, non-unique username: "+ userAuthProfileDto.username());
        }
        UserAuthProfile userAuthProfile = userAuthProfileRepository.save(UserAuthProfile.from(userAuthProfileDto.username(), passwordEncoder.encode(userAuthProfileDto.password())));
        log.info("New userAuthProfile registered and saved. id {} username {}", userAuthProfile.getId(), userAuthProfile.getUsername());
        return userAuthProfile.getId();
    }

    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    @ExceptionHandler( IllegalArgumentException.class)
    public ResponseEntity<String> handleValidationExceptions(
            IllegalArgumentException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(ex.toString());
    }
}
