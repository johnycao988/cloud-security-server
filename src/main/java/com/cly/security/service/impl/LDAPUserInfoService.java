package com.cly.security.service.impl;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Properties;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;

import com.cly.comm.util.IDUtil;
import com.cly.ldap.LDAPContext;
import com.cly.ldap.LDAPSearch;
import com.cly.security.PasswordEncrypt;
import com.cly.security.SecurityAuthException;
import com.cly.security.UserInfo;
import com.cly.security.UserInfoService;

public class LDAPUserInfoService implements UserInfoService {

	private String ldapUserinfoSearchbase;
	private String ldapUserId;
	private String ldapUserPwd;
	private String ldapUserName;

	private String ldapUserGrpId;
	private String ldapUserGrpUserId;
	private String ldapUserGrpSearchbase;

	private static final String ERR_MSG_INVALIDATE_USER_PWD = "Invalidate user or password.";
	private PasswordEncrypt pwdEncrypteService;
	LDAPSearch ldapSearch;

	@Override
	public UserInfo login(String userId, String userPwd) throws SecurityAuthException {

		try {

			if (userId == null || userPwd == null)
				throw new SecurityAuthException("", ERR_MSG_INVALIDATE_USER_PWD);

			Attributes atr = this.ldapSearch.search(ldapUserinfoSearchbase, ldapUserId + "=" + userId,
					SearchControls.SUBTREE_SCOPE);

			if (atr == null)
				throw new SecurityAuthException("", ERR_MSG_INVALIDATE_USER_PWD);

			String slUserPwd = new String((byte[]) atr.get(this.ldapUserPwd).get());

			String slUserName = atr.get(this.ldapUserName).get().toString();

			if (!this.pwdEncrypteService.encrypt(userPwd).equals(slUserPwd))
				throw new SecurityAuthException("", ERR_MSG_INVALIDATE_USER_PWD);

			UserInfoImpl ui = new UserInfoImpl();
			ui.setUserId(userId);
			ui.setUserName(slUserName);
			ui.setAuthCode(IDUtil.getRandomBase64UUID());
			ui.setUserGroups(this.getUserGroups(userId));

			return ui;
		} catch (SecurityAuthException se) {
			throw se;
		} catch (NamingException ne) {
			throw new SecurityAuthException(ne, null, ne.getMessage());
		}
	}

	private String[] getUserGroups(String userId) throws NamingException {

		ArrayList<String> grpList = new ArrayList<String>();

		Attributes[] atrs = this.ldapSearch.multiSearch(this.ldapUserGrpSearchbase, this.ldapUserGrpId + "=*",
				SearchControls.SUBTREE_SCOPE);

		if (atrs == null || atrs.length <= 0)
			return grpList.toArray(new String[0]);

		for (Attributes atr : atrs) {

			String um = this.ldapUserId + "=" + userId + "," + this.ldapUserinfoSearchbase;

			String gid = atr.get(this.ldapUserGrpId).get().toString();

			Attribute at = atr.get(this.ldapUserGrpUserId);

			for (int i = 0; i < at.size(); i++) {
				if (at.get(i).toString().equals(um))
					grpList.add(gid);

			}

		}

		return grpList.toArray(new String[0]);

	}

	@Override
	public void initProperties(Properties prop) throws SecurityAuthException {

		ldapUserinfoSearchbase = prop.getProperty("ldap.user.search.base");
		ldapUserId = LDAPContext.getAttributeMapping(prop, "user.id");
		ldapUserPwd = LDAPContext.getAttributeMapping(prop, "user.pwd");
		ldapUserName = LDAPContext.getAttributeMapping(prop, "user.name");

		this.ldapUserGrpSearchbase = prop.getProperty("ldap.user.group.search.base");
		this.ldapUserGrpId = LDAPContext.getAttributeMapping(prop, "group.id");
		this.ldapUserGrpUserId = LDAPContext.getAttributeMapping(prop, "group.user.id");

		initLdapSearch(prop);

	}

	private void initLdapSearch(Properties p) throws SecurityAuthException {

		try {
			LDAPContext ctx = new LDAPContext();
			ctx.setFactory(p.getProperty("ldap.initial.context.factory"))
					.setPassword(p.getProperty("ldap.server.password"))
					.setSecurityAuthentication(p.getProperty("ldap.context.security.authentication"))
					.setServerUrl(p.getProperty("ldap.server.url")).setUser(p.getProperty("ldap.server.username"));
			this.ldapSearch = new LDAPSearch(ctx);
		} catch (Exception e) {
			throw new SecurityAuthException(e, null, "failed to initial LDAP Search service.");
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

	private String[] listGrp;

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

	public void setUserGroups(String[] listGrp) {
		this.listGrp = listGrp;
	}

	@Override
	public String[] getUserGroups() {
		return listGrp;
	}
 
}
