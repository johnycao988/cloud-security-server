package com.cly.security.server;

import java.util.Properties;
import com.cly.cache.CacheMgr;
import com.cly.cache.KeyValue;
import com.cly.comm.client.config.ConfigClient;
import com.cly.logging.CLYLoggerManager;
import com.cly.security.PasswordEncrypt;
import com.cly.security.SecurityAuthException;
import com.cly.security.UserInfoService;

public class SecurityServiceMgr {

	private static Properties securityProperties = null;
	private static UserInfoService userInfoService = null;
	private static PasswordEncrypt pwdEncryptService = null;
	private static KeyValue kvService;

	private SecurityServiceMgr() {

	}

	public static Properties getProperties() {

		try {
			if (securityProperties == null)
				securityProperties = ConfigClient.getProperties("cloud.security.server.properties");
			return securityProperties;
		} catch (Exception e) {

			CLYLoggerManager.getRootLogger().fatalException(e);
			securityProperties = new Properties();
			return securityProperties;
		}

	}

	public static String refresh(){
		securityProperties = null;
		userInfoService = null;
		pwdEncryptService = null;
		kvService = null;
		initSecurityCache();
		return "Security Server Refresh completed.";
	}

	public static UserInfoService getUserInfoService() throws SecurityAuthException {

		if (userInfoService == null) {
			userInfoService = (UserInfoService) createServiceInstance("cloud.security.userinfo.service");

			userInfoService.initProperties(getProperties());

			userInfoService.setPasswordEncryptService(getPasswordEncryptService());

		}

		return userInfoService;

	}

	public static KeyValue getKVService() throws SecurityAuthException {

		if (kvService == null) {

			kvService = (KeyValue) createServiceInstance("cloud.security.kv.service");

			kvService.initProperties(getProperties());

		}

		return kvService;

	}

	public static PasswordEncrypt getPasswordEncryptService() throws SecurityAuthException {

		if (pwdEncryptService == null) {
			pwdEncryptService = (PasswordEncrypt) createServiceInstance("cloud.security.password.encrypt.service");
		}

		return pwdEncryptService;

	}

	private static Object createServiceInstance(String propName) throws SecurityAuthException {

		try {

			Properties p = getProperties();

			String className = p.getProperty(propName);

			if (className == null) {
				throw new SecurityAuthException(null, "Property:[" + propName + "] is not set.");
			}

			return Class.forName(className).newInstance();

		} catch (Exception e) {
			e.printStackTrace();
			throw new SecurityAuthException(e, null, "Service:" + propName + " failed to initial.");
		}
	}

	public static void initSecurityCache() {
		try {
			CacheMgr.init(ConfigClient.getInputStream("cloud.security.server.cache.xml"));
		} catch (Exception e) {

			CLYLoggerManager.getRootLogger().fatalException(e);
		}
	}

}
