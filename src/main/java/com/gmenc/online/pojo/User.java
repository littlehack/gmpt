package com.gmenc.online.pojo;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public  class User {
    private final String username;
    private final String password;
    private String newpassword;


    public User(String username, String password,String newpassword) {
        this.username = username;
        this.password = password;
        this.newpassword = newpassword;
    }


}
