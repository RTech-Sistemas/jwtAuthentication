package com.rtech.jwtAuthentication.service;

import com.rtech.jwtAuthentication.dto.UserDTO;
import com.rtech.jwtAuthentication.entity.User;
import com.rtech.jwtAuthentication.exception.UserNotFoundException;
import com.rtech.jwtAuthentication.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    @Lazy
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        User user = userRepository.findByname(name);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + name);
        }
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getName())
                .password(user.getPassword())
                .roles(user.getRoles().stream().map(Enum::name).toArray(String[]::new))
                .build();
    }

    public User saveUser(@Valid UserDTO userDTO){
        User user = new User();
        user.setName(userDTO.name());
        user.setPassword(passwordEncoder.encode(userDTO.password()));
        user.setRoles(Set.of(userDTO.role()));

        return userRepository.save(user);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserById(Long id){
        return userRepository.findById(id)
                .orElseThrow(()-> new UserNotFoundException("User not found with id: " + id));
    }

    public User findByName(String name){
        User user = userRepository.findByname(name);
        if (user == null){
            throw new UserNotFoundException("User not found with name: " + name);
        }
        return user;
    }

    public User updateUser(Long id, @Valid UserDTO userDTO) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));

        if (userDTO.name() != null && !userDTO.name().isBlank()) {
            user.setName(userDTO.name());
        }

        if (userDTO.password() != null && !userDTO.password().isBlank()) {
            user.setPassword(passwordEncoder.encode(userDTO.password()));
        }

        if (userDTO.role() != null) {
            user.setRoles(Set.of(userDTO.role()));
        }

        return userRepository.save(user);
    }

    public void deleteUser(Long id){
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
        userRepository.delete(user);
    }
}
