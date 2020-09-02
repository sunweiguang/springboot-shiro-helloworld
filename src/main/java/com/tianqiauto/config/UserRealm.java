package com.tianqiauto.config;

import java.util.ArrayList;
import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class UserRealm extends AuthorizingRealm {

	/**
	 * 身份认证，并返回认证信息 如果认证失败返回空
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		// 获取用户输入的用户名
		String username = (String) token.getPrincipal();
		System.out.println("username == " + username);
		if (username == null || !username.equals("admin")) {
			throw new UnknownAccountException();
		}
		// 假定数据库中的用户密码是 1111
		String pwd = "e379fe9f4bb72d4b76f91febabad3421";
		String salt = "admin";
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(username, pwd, ByteSource.Util.bytes(salt),
				getName());
		return info;
	}

	/**
	 * 获取权限信息
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String username = principals.getPrimaryPrincipal().toString();
		System.out.println("授权=====" + username);
		List<String> permission = new ArrayList<>();
		permission.add("user:view");
		permission.add("user:delete");
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		for (String it : permission) {
			info.addStringPermission(it);
		}
		return info;
	}

	/**
	 * 重写方法,清除当前用户的的 授权缓存
	 * 
	 * @param principals
	 */
	@Override
	public void clearCachedAuthorizationInfo(PrincipalCollection principals) {
		super.clearCachedAuthorizationInfo(principals);
	}

	/**
	 * 重写方法，清除当前用户的 认证缓存
	 * @param principals
	 */
	@Override
	public void clearCachedAuthenticationInfo(PrincipalCollection principals) {
		super.clearCachedAuthenticationInfo(principals);
	}

	@Override
	public void clearCache(PrincipalCollection principals) {
		super.clearCache(principals);
	}

	/**
	 * 自定义方法：清除所有 授权缓存
	 */
	public void clearAllCachedAuthorizationInfo() {
		getAuthorizationCache().clear();
	}

	/**
	 * 自定义方法：清除所有 认证缓存
	 */
	public void clearAllCachedAuthenticationInfo() {
		getAuthenticationCache().clear();
	}

	/**
	 * 自定义方法：清除所有的 认证缓存 和 授权缓存
	 */
	public void clearAllCache() {
		clearAllCachedAuthenticationInfo();
		clearAllCachedAuthorizationInfo();
	}
}
