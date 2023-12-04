package com.gmenc.online.services;

import com.gmenc.online.mapper.DLmapper;
import com.gmenc.online.pojo.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


@Component
public class DLService implements LoginService{

    @Autowired
    private DLmapper dLmapper;

    @Override
    public void login(User user) {
        dLmapper.login(user);

    }
}
