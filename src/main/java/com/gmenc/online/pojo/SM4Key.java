package com.gmenc.online.pojo;

import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;


@Getter
@Setter
public class SM4Key {


    private String iv;

    private String key;

    private String outputType;

    private String planText;

    private String ciphertext;

    private String mode;


}
