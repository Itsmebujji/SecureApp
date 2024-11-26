package com.example.demo.controller;

import com.example.demo.security.JwtTokenUtility;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecureController {
    @Autowired
    private JwtTokenUtility jwtTokenUtility;

    @GetMapping(value = "/getName")
    public String getName(){
        return "Vineethkumar";
    }

    @GetMapping(value = "/auth/accessToken")
    public String getAccessToken(HttpServletRequest header){
        return jwtTokenUtility.generateToken(header);
    }
}
