package com.wgplaner.user;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import jakarta.websocket.server.PathParam;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/password-recovery")
@RequiredArgsConstructor
public class PasswordRecoveryController {
  private final UserAuthProfileRepository userAuthProfileRepository;
  private final PasswordEncoder passwordEncoder;

  @PostMapping(path = "/reset-password")
  public void resetPassword(@RequestBody ResetPasswordDto resetPasswordDto) {
    System.out.println("resetPasswordDto: " + resetPasswordDto);
    UserAuthProfile userAuthProfile = userAuthProfileRepository.findById(resetPasswordDto.oid())
        .orElseThrow(() -> new IllegalArgumentException("UserAuthProfile not found"));
    System.out.println("userAuthProfile: " + userAuthProfile);
    userAuthProfile.setPassword(passwordEncoder.encode(resetPasswordDto.password()));
    userAuthProfileRepository.save(userAuthProfile);
    var g = userAuthProfileRepository.findAll();
    for (var i : g) {
      System.out.println("i: " + i);
    }
    System.out.println("Password reset");
  }

  @ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<String> handleValidationExceptions(IllegalArgumentException ex) {
    log.error(ex.getMessage());
    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(ex.getMessage());
  }
}
