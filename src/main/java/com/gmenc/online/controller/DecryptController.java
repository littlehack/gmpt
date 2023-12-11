package com.gmenc.online.controller;


import com.gmenc.online.pojo.AES;
import com.gmenc.online.pojo.Result;
import com.gmenc.online.pojo.SM2Key;
import com.gmenc.online.pojo.SM4Key;
import com.gmenc.online.services.GmService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Description;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import java.util.logging.Logger;


@Controller
@ResponseBody
@RequestMapping("/api")
@Description("解密接口")
public class DecryptController {

    @Autowired
    private GmService gmService;
    private final Logger logger = Logger.getLogger("Description.class");

    @RequestMapping("/desm2")
    // sm2解密
    public Result desm2(@RequestBody SM2Key sm2Key) {
        try {
            String plantext = gmService.decryptsm2(sm2Key);
            return Result.sunccess(plantext);
        }
        catch (Exception e){
            logger.warning(e.toString());
            return Result.failed("解密失败，请重试");
        }
    }
    @RequestMapping("/desm4")
    public Result desm4(@RequestBody SM4Key sm4Key){
        try {
            String plantext = gmService.decryptsm4(sm4Key);
            return Result.sunccess(plantext);
        }catch (Exception e){
            logger.warning(e.toString());
            return Result.failed("解密失败，请重试");
        }
    }

    @RequestMapping("/deAES")
    public Result deAES(@RequestBody AES aes){
        String result = gmService.deAES(aes);
        return Result.sunccess(result);
    }
}
