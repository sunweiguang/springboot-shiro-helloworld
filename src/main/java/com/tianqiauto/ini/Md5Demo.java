package com.tianqiauto.ini;

import org.apache.shiro.crypto.hash.Md5Hash;

public class Md5Demo {
	public static void main(String[] args) {
		String src = "1111";
		String salt = "admin";
		//MD5加密
		Md5Hash md5 = new Md5Hash(src);
		System.out.println(md5.toString());
		//加盐
		md5 = new Md5Hash(src,salt);
		System.out.println(md5.toString());
		
		//加盐后再加迭代次数
		md5 = new Md5Hash(src,salt,2);
		System.out.println(md5.toString());
	}
}
