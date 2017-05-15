package com.cly.security.service.impl;

import java.io.Serializable;
import java.util.Properties; 
import javax.naming.NamingException;
import javax.naming.directory.Attributes; 
import com.cly.comm.util.IDUtil;
import com.cly.ldap.LDAPContext;
import com.cly.ldap.LDAPSearch;
import com.cly.security.PasswordEncrypt;
import com.cly.security.SecurityServerException;
import com.cly.security.UserInfo;
import com.cly.security.UserInfoService; 

public class LDAPUserInfoService implements UserInfoService {

	private String userinfoSearchbase;
	private String ldapUserId;
	private String ldapUserPwd;
	private String ldapUserName;
	private static final String ERR_MSG_INVALIDATE_USER_PWD = "Invalidate user or password.";
	private PasswordEncrypt pwdEncrypteService;
	LDAPSearch ldapSearch;

	@Override
	public UserInfo login(String userId, String userPwd) throws SecurityServerException {

		try {
	
			if (userId == null || userPwd == null)
				throw new SecurityServerException("", ERR_MSG_INVALIDATE_USER_PWD);

			Attributes atr = this.ldapSearch.search(userinfoSearchbase, ldapUserId + "=" + userId);

			if (atr == null)
				throw new SecurityServerException("", ERR_MSG_INVALIDATE_USER_PWD);

			String slUserPwd = new String((byte[]) atr.get(this.ldapUserPwd).get());

			String slUserName = atr.get(this.ldapUserName).get().toString();

			if (!this.pwdEncrypteService.encrypt(userPwd).equals(slUserPwd))
				throw new SecurityServerException("", ERR_MSG_INVALIDATE_USER_PWD);

			UserInfoImpl ui = new UserInfoImpl();
			ui.setUserId(userId);
			ui.setUserName(slUserName);
			ui.setAuthCode(IDUtil.getRandomBase64UUID());
			return ui;
		} catch (SecurityServerException se) {
			throw se;
		} catch (NamingException ne) {
			throw new SecurityServerException(ne, null, ne.getMessage());
		}
	}

	@Override
	public void initProperties(Properties prop) throws SecurityServerException {

		userinfoSearchbase = prop.getProperty("ldap.user.search.base");
		ldapUserId = LDAPContext.getAttributeMapping(prop, "user.id");
		ldapUserPwd = LDAPContext.getAttributeMapping(prop, "user.pwd");
		ldapUserName = LDAPContext.getAttributeMapping(prop, "user.name");

		initLdapSearch(prop);

	}

	private void initLdapSearch(Properties p) throws SecurityServerException {

		try {
			LDAPContext ctx = new LDAPContext();
			ctx.setFactory(p.getProperty("ldap.initial.context.factory"))
					.setPassword(p.getProperty("ldap.server.password"))
					.setSecurityAuthentication(p.getProperty("ldap.context.security.authentication"))
					.setServerUrl(p.getProperty("ldap.server.url")).setUser(p.getProperty("ldap.server.username"));
			this.ldapSearch = new LDAPSearch(ctx);
		} catch (Exception e) {
			throw new SecurityServerException(e, null, "failed to initial LDAP Search service.");
		}

	}

	@Override
	public void setPasswordEncryptService(PasswordEncrypt pwdService) {
		this.pwdEncrypteService = pwdService;

	}
}

class UserInfoImpl implements UserInfo, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private String userId;

	private String userName;

	private String authCode;

	@Override
	public String getUserId() {
		return this.userId;
	}

	@Override
	public String getUserName() {
		return this.userName;
	}

	@Override
	public String getAuthCode() {
		return this.authCode;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public void setAuthCode(String authCode) {
		this.authCode = authCode;
	}

 

}
