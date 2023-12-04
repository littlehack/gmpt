package com.gmenc.online.pojo;

import org.springframework.stereotype.Component;

@Component
public class Result {
    // code  成功：1  失败：0
    private Integer code;
    private String msg;
    private Object data;

    public Integer getCode() {
        return code;
    }
    public static Result sunccess(Object data){
        return new Result(1,"success", data);
    }
    public static Result failed(Object data){
        return new Result(0,"failed",data);
    }
    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public Result() {
    }

    public Result(Integer code, String msg, Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }
}
