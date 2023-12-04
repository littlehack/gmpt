package com.gmenc.online.pojo;


import lombok.Getter;
import org.springframework.stereotype.Component;


@Getter
public class SM2Key {
    private String mode;
    private String plantext;
    private  String privatekey;
    private  String publickey;

    private String ciphertext;


    public void setPrivatekey(String privatekey) {
        this.privatekey = privatekey;
    }

    public void setPublickey(String publickey) {
        this.publickey = publickey;
    }

    public SM2Key(String plantext, String privatekey, String publickey, String ciphertext, String mode) {
        this.plantext = plantext;
        this.privatekey = privatekey;
        this.mode = mode;
        this.publickey = publickey;
        this.ciphertext = ciphertext;
    }

    public SM2Key(String ciphertext) {
    }


}
