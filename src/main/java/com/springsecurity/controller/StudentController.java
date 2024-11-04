package com.springsecurity.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.model.Student;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class StudentController {
	
	//	List of Students
	private List<Student> students = new ArrayList<>(List.of(
			new Student(1, "Deepak", 90),
			new Student(2, "Kiran", 60)
	));
	
	// Getting all the students	
	@GetMapping("/students")
	public List<Student> getStudents(){
		return students;
	}
	
	//	Getting CSRF Token using HttpServletRequest
	@GetMapping("/csrf-token")
	public CsrfToken getCsrfToken(HttpServletRequest request) {
		return (CsrfToken)request.getAttribute("_csrf");
	}
	
	// Adding the new student into the List of Students	
	@PostMapping("/students")
	public Student addStudent(@RequestBody Student student) {
		students.add(student);
		return student;
	}
}
