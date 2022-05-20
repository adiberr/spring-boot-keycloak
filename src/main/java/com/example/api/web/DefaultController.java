package com.example.api.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DefaultController {

  /**
   * Public
   */
  @GetMapping(value = "/public")
  public String index() {
    return "<h1>It works!</h1>";
  }

  /**
   * Protected
   */
  @GetMapping(value = "/hello")
  public String hello(Authentication authentication) {
    return "Hello, " + authentication.getName();
  }
}
