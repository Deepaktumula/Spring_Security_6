package com.springsecurity.model;

import java.util.Collection;
import java.util.List;
// import java.util.Collections;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UserPrincipal implements UserDetails {
	
	private Users user;
	
	private List<GrantedAuthority> authorities;
	
	public UserPrincipal(Users user) {
		this.user = user;
		this.authorities = List.of(user.getRoles().split(","))
				.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
//		return Collections.singleton(new SimpleGrantedAuthority("USER"));
		return authorities;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUserName();
	}

}
