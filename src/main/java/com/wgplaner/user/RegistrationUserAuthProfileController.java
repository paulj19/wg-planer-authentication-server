package com.wgplaner.user;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;

import javax.validation.Valid;
import java.util.Arrays;
import java.util.Base64;

import static com.wgplaner.config.AuthorizationServerConfig.CLIENT_ID;
import static com.wgplaner.config.AuthorizationServerConfig.CLIENT_PW;

@Slf4j
@RestController
@RequestMapping("/register")
@RequiredArgsConstructor
public class RegistrationUserAuthProfileController {
    private final UserAuthProfileRepository userAuthProfileRepository;
    private final PasswordEncoder passwordEncoder;
    @PostMapping(path = "/new")
    @ResponseStatus(HttpStatus.CREATED)
    public Long register(@RequestBody @Valid UserAuthProfileDto userAuthProfileDto, WebRequest request) {
        if(!authenticate(request)) {
            throw new AuthenticationCredentialsNotFoundException("Basic auth required");
        }
        if( userAuthProfileRepository.findByUsername( userAuthProfileDto.username()) != null ) {
            throw new IllegalArgumentException("New user registration failed, non-unique username: "+ userAuthProfileDto.username());
        }
        UserAuthProfile userAuthProfile = userAuthProfileRepository.save(UserAuthProfile.from(userAuthProfileDto.username(), passwordEncoder.encode(userAuthProfileDto.password()), userAuthProfileDto.floorId()));
        log.info("New userAuthProfile registered and saved. id {} username {} floorId {}", userAuthProfile.getId(), userAuthProfile.getUsername(), userAuthProfile.getFloorId());
        return userAuthProfile.getId();
    }

    private boolean authenticate(WebRequest request){
        String authentication = request.getHeader("Authorization");
        if(authentication == null) {
            return false;
        }
        authentication = authentication.substring(authentication.lastIndexOf("Basic") + 6);
        return Arrays.equals(authentication.getBytes(), getBasicAuth());
    }

    private byte[] getBasicAuth() {
        String auth = CLIENT_ID + ":" + CLIENT_PW;
        return Base64.getEncoder().encode(auth.getBytes());
    }

    @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
    @ExceptionHandler( IllegalArgumentException.class)
    public ResponseEntity<String> handleValidationExceptions(
            IllegalArgumentException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(ex.getMessage());
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler( AuthenticationCredentialsNotFoundException.class)
    public ResponseEntity<String> handleValidationExceptions(
             AuthenticationCredentialsNotFoundException ex) {
        log.error(ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ex.getMessage());
    }
}
