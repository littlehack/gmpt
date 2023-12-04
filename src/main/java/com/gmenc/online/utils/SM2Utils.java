package com.gmenc.online.utils;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static java.util.Objects.isNull;


/**
 * SM2加解密工具类
 */
@Slf4j
public class SM2Utils {
    private static final String EC = "EC";
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static {
        if (isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(PROVIDER);
        }
    }

    // region generateKeyPair

    /**
     * 获取sm2密钥对
     * BC库使用的公钥=64个字节+1个字节（04标志位），BC库使用的私钥=32个字节
     * SM2秘钥的组成部分有 私钥D 、公钥X 、 公钥Y , 他们都可以用长度为64的16进制的HEX串表示，
     * <br/>SM2公钥并不是直接由X+Y表示 , 而是额外添加了一个头
     *
     * @return
     */
    public static SM2KeyPair<byte[], BigInteger> genKeyPair() {
        return genKeyPair(false);
    }

    /**
     * 获取sm2密钥对
     * BC库使用的公钥=64个字节+1个字节（04标志位），BC库使用的私钥=32个字节
     * SM2秘钥的组成部分有 私钥D 、公钥X 、 公钥Y , 他们都可以用长度为64的16进制的HEX串表示，
     * <br/>SM2公钥并不是直接由X+Y表示 , 而是额外添加了一个头，当启用压缩时:公钥=有头+公钥X ，即省略了公钥Y的部分
     *
     * @param compressed 是否压缩公钥（加密解密都使用BC库才能使用压缩）
     * @return
     */
    @SneakyThrows
    public static SM2KeyPair<byte[], BigInteger> genKeyPair(boolean compressed) {
        //1.创建密钥生成器
        KeyPairGeneratorSpi.EC spi = new KeyPairGeneratorSpi.EC();
        //获取一条SM2曲线参数
        X9ECParameters parameters = GMNamedCurves.getByOID(GMObjectIdentifiers.sm2p256v1);
        //构造spec参数
        ECParameterSpec parameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN());
        // SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        SecureRandom secureRandom = new SecureRandom();
        //2.初始化生成器,带上随机数
        spi.initialize(parameterSpec, secureRandom);
        //3.生成密钥对
        KeyPair asymmetricCipherKeyPair = spi.generateKeyPair();
        // 把公钥放入map中,默认压缩公钥
        // 公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04
        BCECPublicKey publicKeyParameters = (BCECPublicKey) asymmetricCipherKeyPair.getPublic();
        ECPoint ecPoint = publicKeyParameters.getQ();
        byte[] publicKey = ecPoint.getEncoded(compressed);
        // 把私钥放入map中
        BCECPrivateKey privateKeyParameters = (BCECPrivateKey) asymmetricCipherKeyPair.getPrivate();
        BigInteger intPrivateKey = privateKeyParameters.getD();
        return new SM2KeyPair<>(publicKey, intPrivateKey);
    }

    public static SM2KeyPair<String, String> genKeyPairAsHex() {
        return genKeyPairAsHex(false);
    }

    public static SM2KeyPair<String, String> genKeyPairAsHex(boolean compressed) {
        final SM2KeyPair<byte[], BigInteger> pair = genKeyPair(compressed);
        return new SM2KeyPair<>(
                Hex.toHexString(pair.getPublic()),
                pair.getPrivate().toString(16)
        );
    }

    public static SM2KeyPair<String, String> genKeyPairAsBase64() {
        return genKeyPairAsBase64(false);
    }

    public static SM2KeyPair<String, String> genKeyPairAsBase64(boolean compressed) {
        final SM2KeyPair<byte[], BigInteger> pair = genKeyPair(compressed);
        return new SM2KeyPair<>(
                BASE64_ENCODER.encodeToString(pair.getPublic()),
                BASE64_ENCODER.encodeToString(pair.getPrivate().toByteArray())
        );
    }

    // endregion generateKeyPair

    // region encrypt

    /**
     * SM2加密算法
     *
     * @param publicKey 公钥
     * @param data      待加密的数据
     * @return 密文，BC库产生的密文带由04标识符，与非BC库对接时需要去掉开头的04
     */
    public static byte[] encrypt(byte[] publicKey, byte[] data) {
        // 按国密排序标准加密
        return encrypt(publicKey, data, SM2Engine.Mode.C1C3C2);
    }

    /**
     * SM2加密算法
     *
     * @param publicKey 公钥
     * @param data      待加密的数据
     * @param mode      密文排列方式
     * @return 密文，BC库产生的密文带由04标识符，与非BC库对接时需要去掉开头的04
     */
    @SneakyThrows
    public static byte[] encrypt(byte[] publicKey, byte[] data, SM2Engine.Mode mode) {
        final ASN1ObjectIdentifier sm2p256v1 = GMObjectIdentifiers.sm2p256v1;
        // 获取一条SM2曲线参数
        X9ECParameters parameters = GMNamedCurves.getByOID(sm2p256v1);
        // 构造ECC算法参数，曲线方程、椭圆曲线G点、大整数N
        ECNamedDomainParameters namedDomainParameters = new ECNamedDomainParameters(
                sm2p256v1, parameters.getCurve(), parameters.getG(), parameters.getN());
        //提取公钥点
        ECPoint pukPoint = parameters.getCurve().decodePoint(publicKey);
        // 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前面的04
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, namedDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(mode);
        SecureRandom secureRandom = new SecureRandom();
        // 设置sm2为加密模式
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, secureRandom));
        final byte[] encrypt = sm2Engine.processBlock(data, 0, data.length);
//        if (encrypt[0] == 0x04) {
//            return Arrays.copyOfRange(encrypt, 1, encrypt.length);
//        }
        return encrypt;
    }

    public static String encryptHex(String publicKey, String data) {
        return encryptHex(publicKey, data, SM2Engine.Mode.C1C3C2);
    }

    public static String encryptHex(String publicKey, String data, SM2Engine.Mode mode) {
        final byte[] key = Hex.decode(publicKey);
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        final byte[] encrypt = encrypt(key, bytes, mode);
        return Hex.toHexString(encrypt);
    }

    public static String encryptBase64(String publicKey, String data) {
        return encryptBase64(publicKey, data, SM2Engine.Mode.C1C3C2);
    }

    public static String encryptBase64(String publicKey, String data, SM2Engine.Mode mode) {
        final byte[] key = BASE64_DECODER.decode(publicKey);
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        final byte[] encrypt = encrypt(key, bytes, mode);
        return BASE64_ENCODER.encodeToString(encrypt);
    }

    // endregion encrypt

    // region decrypt

    /**
     * SM2解密算法
     *
     * @param privateKey 私钥
     * @param cipherData 密文数据
     * @return
     */
    public static byte[] decrypt(BigInteger privateKey, byte[] cipherData) {
        // 按国密排序标准解密
        return decrypt(privateKey, cipherData, SM2Engine.Mode.C1C3C2);
    }

    /**
     * SM2解密算法
     *
     * @param privateKey 私钥
     * @param cipherData 密文数据
     * @param mode       密文排列方式
     * @return
     */
    @SneakyThrows
    public static byte[] decrypt(BigInteger privateKey, byte[] cipherData, SM2Engine.Mode mode) {
        final ASN1ObjectIdentifier sm2p256v1 = GMObjectIdentifiers.sm2p256v1;
        //获取一条SM2曲线参数
        X9ECParameters parameters = GMNamedCurves.getByOID(sm2p256v1);
        // 构造ECC算法参数，曲线方程、椭圆曲线G点、大整数N
        ECNamedDomainParameters namedDomainParameters = new ECNamedDomainParameters(
                sm2p256v1, parameters.getCurve(), parameters.getG(), parameters.getN());
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKey, namedDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(mode);
        // 设置sm2为解密模式
        sm2Engine.init(false, privateKeyParameters);
        // 使用BC库加解密时密文以04开头，传入的密文前面没有04则补上
        if (cipherData[0] == 0x04) {
            return sm2Engine.processBlock(cipherData, 0, cipherData.length);
        } else {
            byte[] bytes = new byte[cipherData.length + 1];
            bytes[0] = 0x04;
            System.arraycopy(cipherData, 0, bytes, 1, cipherData.length);
            return sm2Engine.processBlock(bytes, 0, bytes.length);
        }
    }

    public static String decryptHex(String privateKey, String cipherData) {
        return decryptHex(privateKey, cipherData, SM2Engine.Mode.C1C3C2);
    }

    public static String decryptHex(String privateKey, String cipherData, SM2Engine.Mode mode) {
        final BigInteger key = new BigInteger(privateKey, 16);
        final byte[] decrypt = decrypt(key, Hex.decode(cipherData), mode);
        return new String(decrypt, StandardCharsets.UTF_8);
    }

    public static String decryptBase64(String privateKey, String cipherData) {
        return decryptBase64(privateKey, cipherData, SM2Engine.Mode.C1C3C2);
    }

    public static String decryptBase64(String privateKey, String cipherData, SM2Engine.Mode mode) {
        final BigInteger key = new BigInteger(BASE64_DECODER.decode(privateKey));
        final byte[] decrypt = decrypt(key, BASE64_DECODER.decode(cipherData), mode);
        return new String(decrypt, StandardCharsets.UTF_8);
    }

    // endregion decrypt

    // region sign & cert

    /**
     * 签名
     *
     * @param plainText  待签名文本
     * @param privateKey 私钥
     * @return
     * @throws GeneralSecurityException
     */
    public static String sign(String plainText, BigInteger privateKey) throws GeneralSecurityException {
        X9ECParameters parameters = GMNamedCurves.getByOID(GMObjectIdentifiers.sm2p256v1);
        ECParameterSpec parameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey, parameterSpec);
        PrivateKey bcecPrivateKey = new BCECPrivateKey(EC, privateKeySpec, BouncyCastleProvider.CONFIGURATION);
        // 创建签名对象
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), PROVIDER);
        // 初始化为签名状态
        signature.initSign(bcecPrivateKey);
        // 传入签名字节
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        // 签名
        return BASE64_ENCODER.encodeToString(signature.sign());
    }

    /**
     * 验签
     *
     * @param plainText 待签名文本
     * @param signText
     * @param publicKey 公钥
     * @return
     * @throws GeneralSecurityException
     */
    public static boolean verify(String plainText, String signText, byte[] publicKey) throws GeneralSecurityException {
        X9ECParameters parameters = GMNamedCurves.getByOID(GMObjectIdentifiers.sm2p256v1);
        ECParameterSpec parameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN());
        ECPoint ecPoint = parameters.getCurve().decodePoint(publicKey);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, parameterSpec);
        PublicKey bcecPublicKey = new BCECPublicKey(EC, publicKeySpec, BouncyCastleProvider.CONFIGURATION);
        // 创建签名对象
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), PROVIDER);
        // 初始化为验签状态
        signature.initVerify(bcecPublicKey);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        return signature.verify(BASE64_DECODER.decode(signText));
    }

    /**
     * 证书验签
     *
     * @param certText  证书串
     * @param plainText 签名原文
     * @param signText  签名产生签名值 此处的签名值实际上就是 R和S的sequence
     * @return
     * @throws GeneralSecurityException
     */
    public static boolean certVerify(String certText, String plainText, String signText) throws GeneralSecurityException {
        // 解析证书
        CertificateFactory factory = new CertificateFactory();
        X509Certificate certificate = (X509Certificate) factory.engineGenerateCertificate(
                new ByteArrayInputStream(BASE64_DECODER.decode(certText)));
        // 验证签名
        Signature signature = Signature.getInstance(certificate.getSigAlgName(), PROVIDER);
        signature.initVerify(certificate);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        return signature.verify(BASE64_DECODER.decode(signText));
    }

    // endregion sign & cert

}
