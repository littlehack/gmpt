package com.gmenc.online.mapper;


import com.gmenc.online.pojo.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class DLmapper {

    @Autowired
    private  JdbcTemplate jdbcTemplate;


    public void login(User user) {
        List<Map<String, Object>> list =  jdbcTemplate.queryForList("SELECT user_name,user_pass from admin where user_name=? and user_pass=?",user.getUsername(),user.getPassword());
        System.out.println(list);
    }
}
