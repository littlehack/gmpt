package com.gmenc.online.services;


import com.gmenc.online.pojo.User;
import org.springframework.stereotype.Component;

@Component
public interface LoginService {
    void login(User user);
}
