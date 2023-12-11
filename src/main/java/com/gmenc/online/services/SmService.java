package com.gmenc.online.services;

import com.gmenc.online.mapper.Gmapper;
import com.gmenc.online.pojo.AES;
import com.gmenc.online.pojo.SM2Key;
import com.gmenc.online.pojo.SM4Key;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class SmService implements GmService{

    @Autowired
    private Gmapper gmapper;
    @Override
    public String decryptsm2(SM2Key sm2Key) {
        return  gmapper.decryptsm2(sm2Key);
    }

    @Override
    public String decryptsm4(SM4Key sm4Key) {
        return gmapper.decryptsm4(sm4Key);
    }

    @Override
    public String encryptsm3(String plantext) {
        return gmapper.encryptsm3(plantext);
    }

    @Override
    public String encryptsm2(SM2Key sm2Key) {
        return gmapper.encryptsm2(sm2Key);
    }

    @Override
    public String encryptsm4(SM4Key sm4key) {
        return gmapper.encryptsm4(sm4key);
    }



    @Override
    public String enAes(AES aes){
        return gmapper.enAES(aes);
    }

    @Override
    public String deAES(AES aes) {
        return gmapper.deAES(aes);
    }
}
