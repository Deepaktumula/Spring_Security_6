package com.springsecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.model.Users;
import com.springsecurity.service.UserService;

@RestController
public class UserController {
	
	@Autowired
	private UserService userService;
	
//	Create User
	@PostMapping("/register")
	public Users register(@RequestBody Users user) {
		return userService.register(user);
	}
}
