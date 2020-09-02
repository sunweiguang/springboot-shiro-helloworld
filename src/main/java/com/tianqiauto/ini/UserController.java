package com.tianqiauto.ini;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@Api(tags = "Controller")
public class UserController {
	@ApiOperation(value = "index")
	@GetMapping(value = { "/","/index" })
	public String index() {
		log.debug("index");
		return "index";
	}

	@RequestMapping("logon")
	public ModelAndView login(HttpServletRequest req, Model model) {
		String exceptionClassName = (String) req.getAttribute("shiroLoginFailure");
		String error = null;
		if (UnknownAccountException.class.getName().equals(exceptionClassName)) {
			error = "用户名未找到";
		} else if (IncorrectCredentialsException.class.getName().equals(exceptionClassName)) {
			error = "用户名/密码错误";
		} else if (exceptionClassName != null) {
			error = "其他错误：" + exceptionClassName;
		}
		System.out.println("登录认证："+error);
		model.addAttribute("error", error);
		ModelAndView mv = new ModelAndView("login");
		mv.addObject(model);
		return mv;
	}
	
	/*public ModelAndView app(HttpServletRequest request, HttpSession session, String username, String password,
			String code) {
		ModelAndView mv = new ModelAndView();
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken(username, password);
		try {
			// 下一步到Realm中认证
			subject.login(token);
			mv.setViewName("redirect:index");
			mv.addObject("errMsg", "登陆成功");
			mv.addObject("success", true);
			mv.addObject("code", 0);
			session.setAttribute("userName", username);
		} catch (Exception e) {
			mv.setViewName("login");
			mv.addObject("errMsg", "未知的账号密码");
			mv.addObject("success", false);
			mv.addObject("code", 1);
		}
		return mv;
	}*/

	@GetMapping("toLogin")
	public String toLogin() {
		return "login";
	}
	
	// 如果需要手动处理登出就开启这个
	@RequestMapping("/logout")
	public void logout(HttpServletResponse response) throws IOException {
		SecurityUtils.getSubject().logout();
		response.sendRedirect("/toLogin");
	}

	@GetMapping("noAuth")
	public String nopermit() {
		return "noAuth";
	}
	
	@GetMapping("viewUser")
	@RequiresPermissions(value= {"user:view"})
	@ResponseBody
	public String viewUser() {
		return "you can view this interface!";
	}
	@GetMapping("addUser")
	@RequiresPermissions(value= {"user:add"})
	@ResponseBody
	public String addUser() {
		return "you can view add interface!";
	}

}
