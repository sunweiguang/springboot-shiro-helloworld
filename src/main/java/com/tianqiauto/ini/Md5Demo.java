package com.tianqiauto.ini;

import org.apache.shiro.crypto.hash.Md5Hash;

public class Md5Demo {
	public static void main(String[] args) {
		String src = "1111";
		String salt = "admin";
		//MD5鍔犲瘑
		Md5Hash md5 = new Md5Hash(src);
		System.out.println(md5.toString());
		//鍔犵洂
		md5 = new Md5Hash(src,salt);
		System.out.println(md5.toString());
		
		//鍔犵洂鍚庡啀鍔犺凯浠ｆ鏁�
		md5 = new Md5Hash(src,salt,2);
		System.out.println(md5.toString());
	}
}
