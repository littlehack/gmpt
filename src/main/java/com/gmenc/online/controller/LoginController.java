package com.gmenc.online.controller;


import com.gmenc.online.pojo.Result;
import com.gmenc.online.utils.SM4Utils;
import com.gmenc.online.pojo.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

@Controller
@ResponseBody
@RequestMapping("/api")
public class LoginController {

    private final Logger logger = Logger.getLogger("");

    @Value("${SM4.iv}")
    public String iv;

    @Value("${SM4.key}")
    public String key;


    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * 用户登录
     * @param user
     * @return
     */
    @RequestMapping("/login")
    public Result Login(@RequestBody User user, HttpServletRequest request){
        try {
            Map<String, Object> map = jdbcTemplate.queryForMap("select * from  admin where user_name=?",user.getUsername());
            String plainTextPassword = SM4Utils.decryptHex_CBC(map.get("user_pass").toString(),key,iv, SM4Utils.Padding.PKCS7);
            logger.info("==========" + map + "===========");
            if(plainTextPassword.equals(user.getPassword()) && map.get("user_name").equals(user.getUsername())){
                request.getSession().setAttribute("users", user.getUsername());
                return Result.sunccess("登录成功");
            }
            else {
                return Result.failed("用户名密码错误");
            }
        }catch (Exception e){
            logger.warning(e.getMessage());
            return Result.failed("用户名密码错误");
        }
    }

    /**
     * 用户注册
     * @param user
     * @return
     */
    @RequestMapping("/register")
    public Result RegisterUser(@RequestBody User user){
        //判断注册的用户名是否重复
        List<Map<String, Object>> list =  jdbcTemplate.queryForList("select user_name from admin");
        for(Map<String,Object> userObj : list){
            if(userObj.get("user_name").equals(user.getUsername())){
                logger.warning("用户名重复" + user.getUsername());
                return Result.failed("用户名已经存在!");
            }
        }
        //使用SM4 CBC模式加密数据库中密码
        String EncryptPassword = SM4Utils.encryptHex_CBC(user.getPassword(),key,iv,SM4Utils.Padding.PKCS7);
        jdbcTemplate.update("insert into admin (user_id,user_name,user_pass) values(?,?,?)",UUID.randomUUID().toString(),user.getUsername(),EncryptPassword);
        logger.info("用户名：" + user.getUsername() + "\t密码：" + EncryptPassword);
        return Result.sunccess("注册成功");
    }

    /**
     * 忘记密码
     */

    @RequestMapping("/forget")
    public Result  ForgetPassword(@RequestBody User user){
        String newpassword = SM4Utils.encryptHex_CBC(user.getNewpassword(),key,iv, SM4Utils.Padding.PKCS7);
        int row =  jdbcTemplate.update("update admin set user_pass=? where user_name=?",newpassword,user.getUsername());
        if(row == 0){
            return Result.failed("用户名不存在");
        }
        logger.info("用户" + user.getUsername() + "密码变更为：" + user.getNewpassword());
        return Result.sunccess("密码修改成功");
    }
}
