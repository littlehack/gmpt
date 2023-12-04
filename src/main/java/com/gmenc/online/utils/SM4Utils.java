package com.gmenc.online.utils;

import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import static java.util.Objects.isNull;


/**
 * SM4加解密工具类
 */
@Slf4j
public class SM4Utils {

    private static final int DEFAULT_KEY_SIZE = 128;
    private static final String ALGORITHM = "SM4";
    private static final String SM4_ECB_ = "SM4/ECB/";
    private static final String SM4_CBC_ = "SM4/CBC/";
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static {
        if (isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(PROVIDER);
        }
    }

    @Getter
    public enum Padding {
        PKCS5("PKCS5Padding"),
        PKCS7("PKCS7Padding"),
        ISO10126("ISO10126Padding");

        private final String name;

        Padding(String name) {
            this.name = name;
        }
    }

    // region generateKey

    public static byte[] genKey() {
        return genKey(DEFAULT_KEY_SIZE);
    }

    @SneakyThrows
    public static byte[] genKey(int keySize) {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    public static String genKeyAsHex() {
        return genKeyAsHex(DEFAULT_KEY_SIZE);
    }

    public static String genKeyAsHex(int keySize) {
        return Hex.toHexString(genKey(keySize));
    }

    public static String genKeyAsBase64() {
        return genKeyAsBase64(DEFAULT_KEY_SIZE);
    }

    public static String genKeyAsBase64(int keySize) {
        return BASE64_ENCODER.encodeToString(genKey(keySize));
    }

    // endregion generateKey

    // region ECB mode

    @SneakyThrows
    public static Cipher getCipher_ECB(Padding padding) {
        return Cipher.getInstance(SM4_ECB_ + padding.name, BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * 使用指定的加密算法和密钥对给定的字节数组进行加密
     *
     * @param data 要加密的字节数组
     * @param key  加密所需的密钥
     * @return byte[]   加密后的字节数组
     */
    @SneakyThrows
    public static byte[] encrypt_ECB(byte[] data, byte[] key, Padding padding) {
        Cipher cipher = getCipher_ECB(padding);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    /**
     * 使用指定的加密算法和密钥对给定的字节数组进行解密
     *
     * @param data 要解密的字节数组
     * @param key  解密所需的密钥
     * @return byte[]   解密后的字节数组
     */
    @SneakyThrows
    public static byte[] decrypt_ECB(byte[] data, byte[] key, Padding padding) {
        Cipher cipher = getCipher_ECB(padding);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    public static String encryptHex_ECB(String data, String key, Padding padding) {
        return Hex.toHexString(encrypt_ECB(
                data.getBytes(StandardCharsets.UTF_8),
                Hex.decode(key),
                padding
        ));
    }

    public static String decryptHex_ECB(String data, String key, Padding padding) {
        return new String(decrypt_ECB(
                Hex.decode(data),
                Hex.decode(key),
                padding
        ), StandardCharsets.UTF_8);
    }

    public static String encryptBase64_ECB(String data, String key, Padding padding) {
        return BASE64_ENCODER.encodeToString(encrypt_ECB(
                data.getBytes(StandardCharsets.UTF_8),
                BASE64_DECODER.decode(key),
                padding
        ));
    }

    public static String decryptBase64_ECB(String data, String key, Padding padding) {
        return new String(decrypt_ECB(
                BASE64_DECODER.decode(data),
                BASE64_DECODER.decode(key),
                padding
        ), StandardCharsets.UTF_8);
    }

    // endregion ECB mode

    // region CBC mode

    @SneakyThrows
    public static Cipher getCipher_CBC(Padding padding) {
        return Cipher.getInstance(SM4_CBC_ + padding.name, BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * 使用指定的加密算法和密钥对给定的字节数组进行加密
     *
     * @param data 要加密的字节数组
     * @param key  加密所需的密钥
     * @param iv   解密所需的 IV
     * @return byte[]   加密后的字节数组
     */
    @SneakyThrows
    public static byte[] encrypt_CBC(byte[] data, byte[] key, byte[] iv, Padding padding) {
        Cipher cipher = getCipher_CBC(padding);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(data);
    }

    /**
     * 使用指定的加密算法和密钥对给定的字节数组进行解密
     *
     * @param data 要解密的字节数组
     * @param key  解密所需的密钥
     * @param iv   解密所需的 IV
     * @return byte[]   解密后的字节数组
     */
    @SneakyThrows
    public static byte[] decrypt_CBC(byte[] data, byte[] key, byte[] iv, Padding padding) {
        Cipher cipher = getCipher_CBC(padding);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    public static String encryptHex_CBC(String data, String key, String iv, Padding padding) {
        return Hex.toHexString(encrypt_CBC(
                data.getBytes(StandardCharsets.UTF_8),
                Hex.decode(key),
                Hex.decode(iv),
                padding
        ));
    }

    public static String decryptHex_CBC(String data, String key, String iv, Padding padding) {
        return new String(decrypt_CBC(
                Hex.decode(data),
                Hex.decode(key),
                Hex.decode(iv),
                padding
        ), StandardCharsets.UTF_8);
    }

    public static String encryptBase64_CBC(String data, String key, String iv, Padding padding) {
        return BASE64_ENCODER.encodeToString(encrypt_CBC(
                data.getBytes(StandardCharsets.UTF_8),
                BASE64_DECODER.decode(key),
                BASE64_DECODER.decode(iv),
                padding
        ));
    }

    public static String decryptBase64_CBC(String data, String key, String iv, Padding padding) {
        return new String(decrypt_CBC(
                BASE64_DECODER.decode(data),
                BASE64_DECODER.decode(key),
                BASE64_DECODER.decode(iv),
                padding
        ), StandardCharsets.UTF_8);
    }

    // endregion CBC mode

}
