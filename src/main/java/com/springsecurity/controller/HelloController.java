package com.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class HelloController {
	
	@GetMapping("/")
	public String welcome(HttpServletRequest request) {
		return "Hello World ";
//		return "Hello World " + request.getSession().getId();
	}
}
