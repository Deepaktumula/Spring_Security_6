package com.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.springsecurity.model.Users;

@Repository
public interface UserRepo extends JpaRepository<Users, Integer> {
	
	Users findByUserName(String userName);
}
