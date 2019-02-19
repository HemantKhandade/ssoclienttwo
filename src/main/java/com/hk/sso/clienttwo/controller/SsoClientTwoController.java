package com.hk.sso.clienttwo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/apptwo")
public class SsoClientTwoController {
	@RequestMapping("/home")
    public String index() {
        return "Greetings from Spring Boot!";
    }
}
