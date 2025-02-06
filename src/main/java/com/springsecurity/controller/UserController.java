package com.springsecurity.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.model.UserDTO;
import com.springsecurity.model.Users;
import com.springsecurity.service.JwtService;
import com.springsecurity.service.UserService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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
	@PostMapping("/authentication")
	public ResponseEntity<String> login(@RequestBody Users user, HttpServletResponse response) throws Exception {
		try {

//			Object which check the userName and password with the help of UsernamePasswordAuthenticationToken
			Authentication authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword()));
			if (authentication.isAuthenticated()) {
				
				List<String> roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
//				Based on the userName we are generating the token because different users have different tokens
//				return jwtService.generateToken(user.getUserName());
				
				String token = jwtService.generateToken(user.getUserName(), roles);
				
				Cookie cookie = new Cookie("authToken", token);
				cookie.setSecure(true);
				cookie.setPath("/");
				cookie.setHttpOnly(true);
				cookie.setMaxAge(1 * 60 * 60);
				response.addCookie(cookie);
				return ResponseEntity.status(HttpStatus.OK).body("Login Success");
			}
		} catch (BadCredentialsException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Credentials not matched.Please try again");
		}
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
	}

	@GetMapping("/user")
	@PreAuthorize("hasAuthority('ROLE_USER')")
	public ResponseEntity<UserDTO> userProfile() {
	    UserDTO userDTO = new UserDTO();
	    userDTO.setMessage("Welcome to User Profile");
	    return ResponseEntity.status(HttpStatus.OK).body(userDTO);
	}

	@GetMapping("/admin")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public ResponseEntity<UserDTO> adminProfile() {
	    UserDTO userDTO = new UserDTO();
	    userDTO.setMessage("Welcome to Admin Profile");
	    return ResponseEntity.status(HttpStatus.OK).body(userDTO);
	}

	@GetMapping("/admin/adminProfile")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public ResponseEntity<UserDTO> adminView() {
	    UserDTO userDTO = new UserDTO();
	    userDTO.setMessage("Welcome to Admin View Profile");
	    return ResponseEntity.status(HttpStatus.OK).body(userDTO);
	}
	
	@GetMapping("/roles")
	public List<String> getUserRoles(HttpServletRequest request) {
		List<String> roles = new ArrayList<>();
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : request.getCookies()) {
				if ("authToken".equals(cookie.getName())) {
					String token = cookie.getValue();
					roles = jwtService.extractRoles(token);
					break;
				}
			}
		}
		return roles;
	}

	@GetMapping("/clearCookie")
	public void logOut(HttpServletResponse response) {
		Cookie cookie = new Cookie("authToken", null);
		cookie.setSecure(true);
		cookie.setPath("/");
		cookie.setHttpOnly(true);
		cookie.setMaxAge(0);
		response.addCookie(cookie);
	}
}
