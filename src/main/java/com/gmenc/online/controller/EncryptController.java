package com.gmenc.online.controller;


import com.gmenc.online.pojo.AES;
import com.gmenc.online.pojo.Result;
import com.gmenc.online.pojo.SM2Key;
import com.gmenc.online.pojo.SM4Key;
import com.gmenc.online.services.GmService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Description;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.logging.Logger;

@Controller
@ResponseBody
@RequestMapping("/api")
@Component
public class EncryptController {

    private final Logger logger = Logger.getLogger("");

    @Autowired
    private GmService gmService;
    /**
     * Sm3加密 返回值为Object
     * Sm2加密 json格式传入后端，mode判断加密模式
     * sm4加密 json格式传入后端，mode判断CBC，ECB
     * 所有的响应数据全部为hex格式，如果是text和base64的格式后期需要调整
     * @param plantext
     * @return
     */
    @PostMapping("/ensm3")
    @Description("SM3加密")
    public Result ensm3(@RequestParam String plantext){
        String Ciphertext = gmService.encryptsm3(plantext);
        return Result.sunccess(Ciphertext);
    }


    @PostMapping("/ensm2")
    public Result ensm2(@RequestBody SM2Key sm2Key){
        try{
            String Ciphertext = gmService.encryptsm2(sm2Key);
            return Result.sunccess(Ciphertext);
        }
        catch (Exception e){
            logger.warning(e.getMessage());
            return Result.failed("加密失败，请重试");
        }

    }

    @PostMapping("/ensm4")
    //区分ECB、CBC模式
    //填充方式pkcs5、pkcs7、ISO10126
    public Result ensm4(@RequestBody SM4Key sm4key){
        try {
            String Ciphertext = gmService.encryptsm4(sm4key);
            return Result.sunccess(Ciphertext);
        }catch (Exception e){
            return Result.failed("加密失败，请重试");
        }

    }

    @PostMapping("/enAes")
    public Result enAES(@RequestBody AES aes){
        String result = gmService.enAes(aes);
        return Result.sunccess(result);

    }
}
