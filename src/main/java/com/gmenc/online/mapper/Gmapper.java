package com.gmenc.online.mapper;


import cn.hutool.core.codec.Base64Encoder;
import com.gmenc.online.pojo.AES;
import com.gmenc.online.pojo.SM2Key;
import com.gmenc.online.pojo.SM4Key;
import com.gmenc.online.utils.AESUtils;
import com.gmenc.online.utils.SM2Utils;
import com.gmenc.online.utils.SM3Utils;
import com.gmenc.online.utils.SM4Utils;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.logging.Logger;

@Component
public class Gmapper {

    private final Logger logger = Logger.getLogger("");


    /**
     * SM2加解密
     * @param sm2Key
     * @return
     */
    public String decryptsm2(SM2Key sm2Key) {
        String plantext = "";
        if(sm2Key.getMode().equals("new")){
            plantext = SM2Utils.decryptHex(sm2Key.getPrivatekey(),sm2Key.getCiphertext(), SM2Engine.Mode.C1C3C2);

            logger.info("\n===============解密SM2=============\nSM2_密文：" + sm2Key.getCiphertext() + "\tSM2_明文：" + plantext);
        }
        if(sm2Key.getMode().equals("old")){
            plantext = SM2Utils.decryptHex(sm2Key.getPrivatekey(),sm2Key.getCiphertext(), SM2Engine.Mode.C1C2C3);
            logger.info("\n===============解密SM2=============\nSM2_密文：" + sm2Key.getCiphertext() + "\tSM2_明文：" + plantext);

        }
        return plantext;
    }


    /**
     * SM4加解密
     * @param sm4Key
     * @return
     */
    public String decryptsm4(SM4Key sm4Key) {
        System.out.println(sm4Key.getOutputType());
        String plantext = "";
        if(sm4Key.getMode().equals("ECB") && sm4Key.getOutputType().equals("Base64")){
            plantext = SM4Utils.decryptBase64_ECB(sm4Key.getCiphertext(),Base64Encoder.encode(sm4Key.getKey().getBytes()),SM4Utils.Padding.PKCS7);
            logger.info("\n===============解密SM4=============\nSM4_密文：" + sm4Key.getCiphertext() + "\tSM4_明文：" + plantext);
        } else if (sm4Key.getMode().equals("ECB")) {
            plantext = SM4Utils.decryptHex_ECB(sm4Key.getCiphertext(),sm4Key.getKey(), SM4Utils.Padding.PKCS7);
            logger.info("\n===============解密SM4=============\nSM4_密文：" + sm4Key.getCiphertext() + "\tSM4_明文：" + plantext);
        } else if (sm4Key.getMode().equals("CBC") && sm4Key.getOutputType().equals("Base64")) {
            plantext = SM4Utils.decryptBase64_CBC(sm4Key.getCiphertext(),Base64Encoder.encode(sm4Key.getKey().getBytes()),Base64Encoder.encode(sm4Key.getIv().getBytes()),SM4Utils.Padding.PKCS7);
            logger.info("\n===============解密SM4=============\nSM4_密文：" + sm4Key.getCiphertext() + "\tSM4_明文：" + plantext);
        } else if (sm4Key.getMode().equals("CBC")) {
            plantext = SM4Utils.decryptHex_CBC(sm4Key.getCiphertext(),sm4Key.getKey(),sm4Key.getIv(),SM4Utils.Padding.PKCS7);
            logger.info("\n===============解密SM4=============\nSM4_密文：" + sm4Key.getCiphertext() + "\tSM4_明文：" + plantext);
        }
        return plantext;
    }
        // 1：PKCS7   2：PKCS5  3：ISO10126
        /***
         * TODO 手动补充填充方式
         */
//        String plantext = "";
//        if(sm4Key.getMode().equals("ECB")){
//            plantext = SM4Utils.decryptHex_ECB(sm4Key.getCiphertext(),sm4Key.getKey(), SM4Utils.Padding.PKCS7);
//            logger.info("\n===============解密SM4=============\nSM4_密文：" + sm4Key.getCiphertext() + "\tSM4_明文：" + plantext);
//        }
//        if(sm4Key.getMode().equals("CBC")){
//            plantext = SM4Utils.decryptHex_CBC(sm4Key.getCiphertext(),sm4Key.getKey(),sm4Key.getIv(),SM4Utils.Padding.ISO10126);
//            logger.info("\n===============解密SM4=============\nSM4_密文：" + sm4Key.getCiphertext() + "\tSM4_明文：" + plantext);
//        }
//        return plantext;



    /**
     * SM3摘要计算
     * @param plantext
     * @return
     */
    public String encryptsm3(String plantext) {
        String Ciphertext = SM3Utils.encrypt(plantext);
        logger.info("\n===============加密SM3=============\nSM3_明文：" + plantext+ "\tSM3_密文：" + Ciphertext);
        return Ciphertext;
    }

    public String encryptsm2(SM2Key sm2Key) {
        String sm2data = "";
        // C1C2C3
        if(sm2Key.getMode().equals("old")){
            sm2data = SM2Utils.encryptHex(sm2Key.getPublickey(),sm2Key.getPlantext(), SM2Engine.Mode.C1C2C3);
            logger.info("\n===============加密SM2=============\nSM2_明文：" + sm2Key.getPlantext() + "\tSM2_密文：" + sm2data);
        }

        // C1C3C2
        if(sm2Key.getMode().equals("new")){
            sm2data = SM2Utils.encryptHex(sm2Key.getPublickey(),sm2Key.getPlantext(), SM2Engine.Mode.C1C3C2);
            logger.info("\n===============加密SM2=============\nSM2_明文：" + sm2Key.getPlantext() + "\tSM2_密文：" + sm2data);
        }
        return sm2data;
    }

    public String encryptsm4(SM4Key sm4key) {
        String sm4data = "";
        if(sm4key.getMode().equals("ECB") && sm4key.getOutputType().equals("Base64")){
            sm4data = SM4Utils.encryptBase64_ECB(sm4key.getPlanText(),Base64Encoder.encode(sm4key.getKey().getBytes()),SM4Utils.Padding.PKCS7);
            logger.info("\n===============加密SM4=============\nSM4_明文：" + sm4key.getPlanText() + "\tSM4_密文：" + sm4data);
        } else if (sm4key.getMode().equals("ECB")) {
            sm4data = SM4Utils.encryptHex_ECB(sm4key.getPlanText(),sm4key.getKey(), SM4Utils.Padding.PKCS7);
            logger.info("\n===============加密SM4=============\nSM4_明文：" + sm4key.getPlanText() + "\tSM4_密文：" + sm4data);
        } else if (sm4key.getMode().equals("CBC") && sm4key.getOutputType().equals("Base64")) {
            sm4data = SM4Utils.encryptBase64_CBC(sm4key.getPlanText(),Base64Encoder.encode(sm4key.getKey().getBytes()),Base64Encoder.encode(sm4key.getIv().getBytes()),SM4Utils.Padding.PKCS7);
            logger.info("\n===============加密SM4=============\nSM4_明文：" + sm4key.getPlanText() + "\tSM4_密文：" + sm4data);

        } else if (sm4key.getMode().equals("CBC")) {
            sm4data = SM4Utils.encryptHex_CBC(sm4key.getPlanText(),sm4key.getKey(),sm4key.getIv(),SM4Utils.Padding.PKCS7);
            logger.info("\n===============加密SM4=============\nSM4_明文：" + sm4key.getPlanText() + "\tSM4_密文：" + sm4data);
        }
        return sm4data;
    }



    /**
     * AES 加密
     * @param aes
     * @return
     */

    public String enAES(AES aes) {
        String cipher = "";
        if(aes.getMode().equals("ECB")){
            cipher =  AESUtils.encryptECB(aes.getPlaintext(),aes.getKey());
            logger.info("\n===============加密AES=============\nAES_明文：" + aes.getPlaintext() + "\tAES_密文：" + cipher);

        }
        if(aes.getMode().equals("CBC")){
            cipher = AESUtils.encryptCBC(aes.getPlaintext(),aes.getKey(),aes.getIv());
            logger.info("\n===============加密AES=============\nAES_明文：" + aes.getPlaintext() + "\tAES_密文：" + cipher);

        }
        return cipher;
    }

    public String deAES(AES aes) {
        String plaintext = "";
        if(aes.getMode().equals("ECB")){
            plaintext =  AESUtils.decryptECB(aes.getCiphertext(),aes.getKey());
            logger.info("\n===============解密AES=============\nAES_密文：" + aes.getCiphertext() + "\tAES_明文：" + plaintext);

        }
        if(aes.getMode().equals("CBC")){
            plaintext = AESUtils.decryptCBC(aes.getCiphertext(),aes.getKey(),aes.getIv());
            logger.info("\n===============解密AES=============\nAES_密文：" + aes.getCiphertext() + "\tAES_明文：" + plaintext);

        }
        return plaintext;
    }
}

