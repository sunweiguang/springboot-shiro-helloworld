package com.tianqiauto.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.web.servlet.DispatcherServletAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.web.filter.DelegatingFilterProxy;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
public class ShiroConfig {

	/**
	 * 注册过滤器
	 */
	@Bean
	public FilterRegistrationBean<DelegatingFilterProxy> filterRegistrationBeanDelegatingFilterProxy() {
		FilterRegistrationBean<DelegatingFilterProxy> bean = new FilterRegistrationBean<>();
		// 创建过滤器
		DelegatingFilterProxy proxy = new DelegatingFilterProxy();
		proxy.setTargetBeanName("shiroFilter");
		proxy.setTargetFilterLifecycle(true);
		bean.setFilter(proxy);
		List<String> servletNames = new ArrayList<>();
		servletNames.add(DispatcherServletAutoConfiguration.DEFAULT_DISPATCHER_SERVLET_BEAN_NAME);
		bean.setServletNames(servletNames);
		return bean;
	}

	@Bean(name = "shiroFilter")
	public ShiroFilterFactoryBean shirFilter(@Qualifier("securityManager") DefaultWebSecurityManager securityManager) {
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		// 设置安全管理器
		shiroFilterFactoryBean.setSecurityManager(securityManager);
		// 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
		shiroFilterFactoryBean.setLoginUrl("/logon");
		// 登录成功后要跳转的链接
		shiroFilterFactoryBean.setSuccessUrl("/index");
		// 未授权时跳转的提示界面
		shiroFilterFactoryBean.setUnauthorizedUrl("/noAuth");

		// 这里需要LinkedHashMap 不能HashMap （坑点之一：会出现代码已经配置却依然无权限访问的问题）
		Map<String, String> filterMap = new LinkedHashMap<String, String>();
		filterMap.put("/css/**", "anon");
		filterMap.put("/img/**", "anon");
		filterMap.put("/js/**", "anon");
		filterMap.put("/**/*.js", "anon");
		filterMap.put("/**/*.css", "anon");
		filterMap.put("/**/*.ico", "anon");
		filterMap.put("/csrf", "anon");

		filterMap.put("/webjars/**", "anon");
		filterMap.put("/swagger**/**", "anon");
		filterMap.put("/v2/api-docs", "anon");
		filterMap.put("classpath:/META-INF/resources/", "anon");
		filterMap.put("classpath:/META-INF/resources/webjars/", "anon");

		filterMap.put("/html/**", "anon");
		filterMap.put("/toLogin", "anon");
		filterMap.put("/index", "authc");

		// 配置退出 过滤器,其中的具体的退出代码Shiro已经实现
		// filterMap.put("/login", "anon");
		// filterMap.put("/logout", "logout");

		filterMap.put("/", "authc");
		filterMap.put("/**", "authc");// 过滤链定义，从上向下顺序执行，一般将/**放在最为下边
		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterMap);

		// 注册filters
		// Map<String, Filter> filters = shiroFilterFactoryBean.getFilters();
		// filters.put("authc", loginFilter());
		// filters.put("logout", logoutFilter());

		return shiroFilterFactoryBean;

	}

	public LogoutFilter logoutFilter() {
		LogoutFilter logout = new LogoutFilter();
		logout.setRedirectUrl("toLogin");
		return logout;
	}

	/* 修改 authc 过滤器，可以调整登录后的跳转页面，登录界面的认证参数 */
	public FormAuthenticationFilter loginFilter() {
		FormAuthenticationFilter loginFilter = new FormAuthenticationFilter();
		loginFilter.setUsernameParam("username");
		loginFilter.setPasswordParam("password");
		loginFilter.setSuccessUrl("/index");
		return loginFilter;
	}

	/**
	 * 权限管理，配置主要是Realm的管理认证
	 */
	@Bean(name = "securityManager")
	public DefaultWebSecurityManager securityManager(@Qualifier("myShiroRealm") UserRealm realm,
			@Qualifier("cacheManager") CacheManager cacheManager) {
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setRealm(realm);
		//配置redis缓存
		securityManager.setCacheManager(cacheManager);
		securityManager.setSessionManager(sessionManager());

		return securityManager;
	}

	/**
	 * 将自己的验证方式加入容器
	 */
	@Bean(name = "myShiroRealm")
	public UserRealm myShiroRealm(
			@Qualifier("hashedCredentialsMatcher") HashedCredentialsMatcher hashedCredentialsMatcher) {
		UserRealm myShiroRealm = new UserRealm();
		myShiroRealm.setCredentialsMatcher(hashedCredentialsMatcher);
		return myShiroRealm;
	}

	@Bean
	public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
		DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
		creator.setProxyTargetClass(true);
		return creator;
	}

	// 凭证匹配器（由于密码校验交给Shiro的SimpleAuthenticationInfo进行处理了）
	@Bean(name = "hashedCredentialsMatcher")
	public HashedCredentialsMatcher hashedCredentialsMatcher() {
		HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
		hashedCredentialsMatcher.setHashAlgorithmName("md5");// 散列算法:这里使用MD5算法;
		hashedCredentialsMatcher.setHashIterations(2);// 散列的次数，比如散列两次，相当于 md5(md5(""));
		return hashedCredentialsMatcher;
	}

	/**
	 * Shiro生命周期处理器
	 */
	@Bean(name = "lifecycleBeanPostProcessor")
	public static LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
		return new LifecycleBeanPostProcessor();
	}

	/**
	 * 开启Shiro的注解(如@RequiresRoles,@RequiresPermissions),需借助SpringAOP扫描使用Shiro注解的类,并在必要时进行安全逻辑验证
	 */
	@Bean
	@DependsOn("lifecycleBeanPostProcessor")
	public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
		DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
		creator.setProxyTargetClass(true);
		return creator;
	}

	/**
	 * 开启shiro aop注解支持. 使用代理方式;所以需要开启代码支持;
	 */
	@Bean
	public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(
			@Qualifier("securityManager") DefaultWebSecurityManager securityManager) {
		AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
		authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
		return authorizationAttributeSourceAdvisor;
	}

	// 缓存，每次权限检测会到数据库中获取对应的权限信息，效率低下，
	// 可以结合缓存将数据存储在缓存中，提高系统的相应效率
	// 配置一个缓存管理器
	// RedisManager 插件
    @Bean
    public RedisManager redisManager(){
        RedisManager redisManager = new RedisManager();
        redisManager.setHost("127.0.0.1:6379");
        return redisManager;
    }
    
    @Bean
    public RedisSessionDAO getRedisSessionDAO() {
    	RedisSessionDAO dao = new RedisSessionDAO();
    	dao.setRedisManager(redisManager());
    	return dao;
    }

    @Bean
    public DefaultWebSessionManager sessionManager() {
    	DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
    	sessionManager.setSessionDAO(getRedisSessionDAO());
    	return sessionManager;
    }
    
    @Bean(name="cacheManager")
    public RedisCacheManager cacheManager() {
    	RedisCacheManager cacheManager = new RedisCacheManager();
    	cacheManager.setRedisManager(redisManager());
    	return cacheManager;
    }
}
