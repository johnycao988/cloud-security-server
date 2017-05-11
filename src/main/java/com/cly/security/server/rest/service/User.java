package com.cly.security.server.rest.service;

import javax.inject.Singleton;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.cly.cache.KeyValue;
import com.cly.comm.client.http.HttpRequestParam;
import com.cly.comm.util.JSONUtil;
import com.cly.security.server.SecurityServiceMgr;
import com.cly.security.user.UserInfo;
import com.cly.security.server.App;
import com.cly.security.server.SecurityServerException;

@Singleton
@Path("/user")
public class User {

	private static String USER_AUTH_CODE="USER.AUTH.CODE";
	
	@POST
	@Path("/login")
	@Produces(MediaType.APPLICATION_JSON)
	public String validate(@FormParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		try {

			UserInfo ui= SecurityServiceMgr.getUserInfoService().login(jsonMsg);
			
			KeyValue kvs=SecurityServiceMgr.getKVService();
			
			kvs.set(this.getKVAuthCodeName(ui.getAuthCode()),ui.getUserId());
			
			return JSONUtil.initSuccess().toString();			
			
			
		} catch (SecurityServerException e) {
			return JSONUtil.initFailed(e).toString();
		} 
	}
	
	
	private String getKVAuthCodeName(String authCode){
		return App.APP_PATH+"."+USER_AUTH_CODE+":"+authCode;
	}
	

	
}
