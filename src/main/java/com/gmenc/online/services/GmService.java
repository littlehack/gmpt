package com.gmenc.online.services;

import com.gmenc.online.pojo.AES;
import com.gmenc.online.pojo.SM2Key;
import com.gmenc.online.pojo.SM4Key;
import org.springframework.stereotype.Component;

@Component
public interface GmService {

    //sm2解密
    String decryptsm2(SM2Key sm2Key);


    //sm4解密
    String decryptsm4(SM4Key sm4Key);

    String encryptsm3(String plantext);

    String encryptsm2(SM2Key sm2Key);

    String encryptsm4(SM4Key sm4key);

    String enAes(AES aes);

    String deAES(AES aes);
}
