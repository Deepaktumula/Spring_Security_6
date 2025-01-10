package com.springsecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.model.Users;
import com.springsecurity.service.JwtService;
import com.springsecurity.service.UserService;

@RestController
public class UserController {
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private JwtService jwtService;
	
	@Autowired
	AuthenticationManager authenticationManager;
	
//	Create User
	@PostMapping("/register")
	public Users register(@RequestBody Users user) {
		return userService.register(user);
	}
	
//	User Login
	@PostMapping("/login")
	public String login(@RequestBody Users user) {
		
//		Object which check the userName and password with the help of UsernamePasswordAuthenticationToken
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword()));
		if(authentication.isAuthenticated()) {
//			Based on the userName we are generating the token because different users have different tokens
			return jwtService.generateToken(user.getUserName());
		}else {
			return "Login Failed";
		}
		
	}
}
