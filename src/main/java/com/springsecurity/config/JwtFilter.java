package com.springsecurity.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.springsecurity.service.JwtService;
import com.springsecurity.service.MyUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	JwtService jwtService;

	@Autowired
	ApplicationContext context;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String authHeader = request.getHeader("Authorization");
		String token = null;
		String userName = null;

		if (authHeader != null && authHeader.startsWith("Bearer ")) {
//			Extracting only token
			token = authHeader.substring(7);
//			Extracting UserName
			userName = jwtService.extractUserName(token);

		}
//		Checking whether the UserName is present or not and checking if it is already authenticated before or not
		if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//			Getting the User Details from this
			UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(userName);
//			sending token and UserDetails to validate the token
			if (jwtService.validateToken(token, userDetails)) {
//				Creating the token for newly logged in User
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
						null, userDetails.getAuthorities());
//				Now setting the details inside the Spring Security Context
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
//		To continue the Filter chain we need to send request and response object
		filterChain.doFilter(request, response);
	}

}
