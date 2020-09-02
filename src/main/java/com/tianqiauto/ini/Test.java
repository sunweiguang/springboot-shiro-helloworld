package com.tianqiauto.ini;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

@SuppressWarnings("deprecation")
public class Test {
	public static void main(String[] args) {
		// 1. 创建securityManager 工厂
		Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
		// 2. 从工厂中获取SecurityManager的实例
		SecurityManager manager = factory.getInstance();
		// 3. 将securityManager的实例放到运行环境中
		SecurityUtils.setSecurityManager(manager);
		// 4. 通过securityUtil获取subject
		Subject subject = SecurityUtils.getSubject();
		// 5. 验证登录
		// 这里的用户名密码模拟的是从界面提交的用户名密码
		UsernamePasswordToken token = new UsernamePasswordToken("admin","1111");
		
		// 6.验证用户是否正常
		try {
			subject.login(token);
			if(subject.isAuthenticated()) {
				System.out.println("登录成功！");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		// 6.验证授权 
		System.out.println(subject.isPermittedAll("user:addd"));
		// 7. 
	}
}
