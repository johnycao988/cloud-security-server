package com.cly.security.server.rest.service;

import javax.inject.Singleton;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import com.cly.cache.KeyValue;
import com.cly.comm.client.http.HttpRequestParam;
import com.cly.comm.util.IDUtil;
import com.cly.comm.util.JSONUtil;
import com.cly.security.server.SecurityServiceMgr;
import com.cly.security.user.UserInfo;
import net.sf.json.JSONObject;
import com.cly.security.server.SecuConst;
import com.cly.security.server.SecurityServerException;

@Singleton
@Path("/user")
public class User {

	@POST
	@Path("/pageLogin")
	@Produces(MediaType.APPLICATION_JSON)
	public String pageLogin(@FormParam(SecuConst.USER_ID) String userId, @FormParam(SecuConst.USER_PW) String userPwd ) {
		
		return login(userId, userPwd);
	}

	@POST
	@Path("/msgLogin")
	@Produces(MediaType.APPLICATION_JSON)
	public String msgLogin(@FormParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		JSONObject msg = JSONObject.fromObject(jsonMsg);

		String userId = msg.getString(SecuConst.USER_ID);

		String userPwd = msg.getString(SecuConst.USER_PW);
		
		return login(userId, userPwd);

	}

	private String login(String userId, String userPwd) {

		try {

			UserInfo ui = SecurityServiceMgr.getUserInfoService().login(userId, userPwd);

			KeyValue kvs = SecurityServiceMgr.getKVService();

			kvs.set(this.getKVAuthCodeName(ui.getAuthCode()), ui.getUserId(), 30 * 60);

			String inqCode = IDUtil.getRandomBase64UUID();

			kvs.set(this.getKVInqAuthCodeName(inqCode), ui.getAuthCode(), 30);

			JSONObject resMsg = JSONUtil.initSuccess();

			resMsg.put(SecuConst.AUTH_INQ_CODE, inqCode);

			return resMsg.toString();

		} catch (SecurityServerException e) {
			return JSONUtil.initFailed(e).toString();
		}

	}

	private String getKVAuthCodeName(String authCode) {
		return SecuConst.APP_PATH + "." + SecuConst.AUTH_CODE + ":" + authCode;
	}

	private String getKVInqAuthCodeName(String inqCode) {
		return SecuConst.APP_PATH + "." + SecuConst.AUTH_INQ_CODE + ":" + inqCode;
	}

}
