package com.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
// Used to Enable Custom Security
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtFilter jwtFilter;
		
//	Returning the SecurityFilterChain Object by customizing the Security
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return	http.csrf(customizer -> customizer.disable())
				.authorizeHttpRequests(request -> request
						.requestMatchers("register", "authentication", "clearCookie").permitAll()
						.requestMatchers("/user/**").hasAuthority("ROLE_USER")
						.requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
						.anyRequest().authenticated())
				.formLogin(formLogin ->{
					formLogin.loginPage("/login").permitAll();
				})
//				.formLogin(form -> form.loginPage("/login") // Custom login page URL
//						.loginProcessingUrl("/auth/login") // URL to submit the credentials
//						.usernameParameter("username") // UserName parameter name in the form
//						.passwordParameter("password") // Password parameter name in the form
//						// Redirect after successful login
//						.failureUrl("/login?error=true") // Redirect after failed login
//						.permitAll())
//				.logout(logout -> logout.logoutUrl("/auth/logout") // Logout URL
//						.logoutSuccessUrl("/login?logout=true") // Redirect after logout
//						.deleteCookies("jwt") // Clear cookies on logout
//						.permitAll())
				.httpBasic(Customizer.withDefaults())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}
	
//	Which is used to verify the Customized authentication 
//	This is also an Interface and we need to return the Object of type AuthenticationProvider 
//	so we need to use help of another class again DAOAuthenticationProvider which implements 
//	AbstractUserDetailsAuthenticationProvider and this class implements our AuthenticationProvider
	@Bean
	AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//		Decoding the Password
		provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
		provider.setUserDetailsService(userDetailsService);
		return provider;
	}
	
	
//	Creating the bean for Authentication Manager
	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
		
	}
	
}
