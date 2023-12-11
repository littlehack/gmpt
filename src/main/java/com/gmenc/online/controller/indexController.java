package com.gmenc.online.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class indexController {
    @RequestMapping("/index")
    public String index(){
        return "index";
    }

    @RequestMapping("/register")
    public String register(){
        return "register";
    }

    @RequestMapping("/login/SM2")
    public String SM2(){
        return "SM2";
    }
    @RequestMapping("/login/SM3")
    public String SM3(){
        return "SM3";
    }
    @RequestMapping("/login/SM4")
    public String SM4(){
        return "SM4";
    }

    @RequestMapping("/login/AES")
    public String AES(){
        return "AES";
    }
    @RequestMapping("/forget")
    public String forget(){
        return "forget";
    }

}
