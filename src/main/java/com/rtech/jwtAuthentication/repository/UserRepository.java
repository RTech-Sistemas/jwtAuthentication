package com.rtech.jwtAuthentication.repository;

import com.rtech.jwtAuthentication.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Long> {
    User findByname(String name);
}
