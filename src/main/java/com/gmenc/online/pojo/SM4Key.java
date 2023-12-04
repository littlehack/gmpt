package com.gmenc.online.pojo;

import lombok.Getter;
import org.springframework.stereotype.Component;


@Getter
public class SM4Key {
    private String iv;
    private String key;

    private String plantext;

    public SM4Key(String iv, String key, String plantext, String ciphertext, Integer padding, String mode) {
        this.iv = iv;
        this.key = key;
        this.plantext = plantext;
        this.ciphertext = ciphertext;
        this.padding = padding;
        this.mode = mode;
    }

    private String ciphertext;

    private Integer padding;


    private String mode;


    public void setKey(String key) {
        this.key = key;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

}
