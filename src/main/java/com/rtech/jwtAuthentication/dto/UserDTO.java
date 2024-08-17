package com.rtech.jwtAuthentication.dto;

import com.rtech.jwtAuthentication.enums.Role;



public record UserDTO(String name, String password, Role role) {


}
