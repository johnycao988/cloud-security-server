package com.cly.security.server;

import java.util.Properties;
import com.cly.cache.CacheMgr;
import com.cly.cache.KeyValue;
import com.cly.comm.client.config.ConfigClient;
import com.cly.err.ErrorHandler;
import com.cly.err.ErrorHandlerMgr;
import com.cly.logging.CLYLogger;
import com.cly.logging.CLYLoggerManager;
import com.cly.security.SecurityAuthException;
import com.cly.security.UserInfoService;

public class SecurityServiceMgr {

	private static Properties securityProperties = null;

	private static UserInfoService userInfoService = null;

	private static KeyValue kvService;

	private SecurityServiceMgr() {

	}

	public static Properties getProperties() {

		return securityProperties;
	}

	public static String refresh() {

		CLYLoggerManager.getRootLogger().info("Start to refresh security server configurations...");
		
		init();

		return "Security Server Refresh completed.";
	}

	public static UserInfoService getUserInfoService() throws SecurityAuthException {

		if (userInfoService == null) {

			userInfoService = (UserInfoService) createServiceInstance("cloud.security.userinfo.service");

			userInfoService.initProperties(getProperties());

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

	private static Object createServiceInstance(String propName) throws SecurityAuthException {

		ErrorHandler eh = ErrorHandlerMgr.getErrorHandler();

		Properties p = getProperties();

		String className = p.getProperty(propName);

		if (className == null) {
			String errCode = "SECU-00002";
			String errMsg=eh.getErrorMessage(errCode, propName);
			CLYLoggerManager.getRootLogger().fatal(errMsg);
			throw new SecurityAuthException(errCode, errMsg);
		}

		try {

			return Class.forName(className).newInstance();

		} catch (Exception e) {
			String errCode = "SECU-00003";
			String errMsg=eh.getErrorMessage(errCode, propName);
			CLYLoggerManager.getRootLogger().fatal(errMsg);
			throw new SecurityAuthException(e,errCode, errMsg);
		}
	}

	public static void init() {

		try {

			securityProperties = null;

			userInfoService = null;

			kvService = null;

			CLYLoggerManager.initPropertiesConfig(
					ConfigClient.getInputStream("/cloud.security/cloud.security.server.log4j.properties"));

			CLYLogger logger=CLYLoggerManager.getRootLogger();
			
			logger.info("Initializing Error Handler...");
			ErrorHandlerMgr.clear();

			ErrorHandlerMgr
					.addConfigFile(ConfigClient.getInputStream("/cloud.security/cloud.security.err.handler.xml"));

			logger.info("Initializing Cache...");
			
			CacheMgr.init(ConfigClient.getInputStream("/cloud.security/cloud.security.server.cache.xml"));

			logger.info("Initializing Properties...");
			securityProperties = ConfigClient.getProperties("/cloud.security/cloud.security.server.properties");

			CLYLoggerManager.getRootLogger().info("Initialized completely.");

		} catch (Exception e) {

			CLYLoggerManager.getRootLogger().fatalException(e);

		}
	}

}
