package com.gmenc.online.utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;


public class AESUtils {

    private static final String ALGORITHM = "AES";
    private static final String ECB_TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String CBC_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String CHARSET = "UTF-8";

    public static String encryptECB(String plaintext, String key) {
        try {
            Cipher cipher = Cipher.getInstance(ECB_TRANSFORMATION);
            SecretKey secretKey = generateKey(key);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(CHARSET));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptECB(String ciphertext, String key) {
        try {
            Cipher cipher = Cipher.getInstance(ECB_TRANSFORMATION);
            SecretKey secretKey = generateKey(key);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decryptedBytes, CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptCBC(String plaintext, String key, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(CBC_TRANSFORMATION);
            SecretKey secretKey = generateKey(key);
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(CHARSET));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(CHARSET));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptCBC(String ciphertext, String key, String iv) {
        try {
            Cipher cipher = Cipher.getInstance(CBC_TRANSFORMATION);
            SecretKey secretKey = generateKey(key);
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv.getBytes(CHARSET));
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decryptedBytes, CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static SecretKey generateKey(String key) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(128, new SecureRandom(key.getBytes()));
        return keyGenerator.generateKey();
    }

    public static void main(String[] args) {
        String key = "1111111111111111"; // 16字节的密钥
        String iv = "1111111111111111"; // 16字节的初始化向量

        String plaintext = "Hello, AES!";
        System.out.println("原文: " + plaintext);

        String encryptedTextECB = encryptECB(plaintext, key);
        System.out.println("ECB模式加密后: " + encryptedTextECB);

        String decryptedTextECB = decryptECB(encryptedTextECB, key);
        System.out.println("ECB模式解密后: " + decryptedTextECB);

        String encryptedTextCBC = encryptCBC(plaintext, key, iv);
        System.out.println("CBC模式加密后: " + encryptedTextCBC);

        String decryptedTextCBC = decryptCBC(encryptedTextCBC, key, iv);
        System.out.println("CBC模式解密后: " + decryptedTextCBC);
    }
}

