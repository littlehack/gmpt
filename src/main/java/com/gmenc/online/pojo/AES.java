package com.gmenc.online.pojo;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AES {
    public String iv;
    public String key;
    public String mode;
    public String plaintext;
    public String ciphertext;
}
