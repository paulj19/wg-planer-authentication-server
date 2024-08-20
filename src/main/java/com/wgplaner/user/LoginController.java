package com.wgplaner.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
  @GetMapping("/login")
  public String login() {
    return "login";
  }
  @GetMapping("/forgot-password")
  public String forgotPassword() {
    return "forgot-password";
  }
}
