package com.cly.security.server.rest.service;

import java.io.IOException;

import javax.inject.Singleton;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import com.cly.cache.CacheMgr;
import com.cly.cache.KeyValue;
import com.cly.comm.client.http.HttpRequestParam;
import com.cly.comm.util.IDUtil;
import com.cly.comm.util.JSONResult;
import com.cly.comm.util.JSONUtil;
import com.cly.security.server.SecurityServiceMgr;

import net.sf.ehcache.Cache;
import net.sf.ehcache.Element;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import com.cly.security.SecuConst;
import com.cly.security.SecurityAuthException;
import com.cly.security.UserInfo;

@Singleton
@Path("/user")
public class User {

	private static final String ERR_MSG_INVALIDATE_USER_OR_AUTHCODE = "Invalidate User or Auth Code.";
	private static final String ERR_MSG_INVALIDATE_INQ_AUTHCODE = "Invalidate Inquire Auth Code.";

	@POST
	@Path("/authUserGrps")
	@Produces(MediaType.APPLICATION_JSON)
	public String authUserGrps(@FormParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		try {

			JSONObject msg = JSONObject.fromObject(jsonMsg);

			String userId = JSONUtil.getString(msg, SecuConst.USER_ID);

			String authCode = JSONUtil.getString(msg, SecuConst.AUTH_CODE);

			Cache sessCache = CacheMgr.getCache(SecuConst.AUTH_CODE_CACHE);

			UserInfo ui = (UserInfo) sessCache.get(authCode).getObjectValue();

			if (ui == null) {

				KeyValue kvs = SecurityServiceMgr.getKVService();

				String uif = kvs.get(this.getKVAuthCodeName(authCode));

				if (uif == null)
					throw new SecurityAuthException("", ERR_MSG_INVALIDATE_USER_OR_AUTHCODE);

				SessionUserInfo sui = new SessionUserInfo(uif);
				ui = sui;
				sessCache.put(new Element(ui.getAuthCode(), ui));

			}

			if (!ui.getUserId().equals(userId) && !ui.getAuthCode().equals(authCode))
				throw new SecurityAuthException("", ERR_MSG_INVALIDATE_USER_OR_AUTHCODE);

			return JSONUtil.initSuccess().toString();

		} catch (SecurityAuthException e) {
			return JSONUtil.initFailed(e).toString();
		}

	}
	
	@POST
	@Path("/validate")
	@Produces(MediaType.APPLICATION_JSON)
	public String validate(@FormParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		try {

			JSONObject msg = JSONObject.fromObject(jsonMsg);

			String userId = JSONUtil.getString(msg, SecuConst.USER_ID);

			String authCode = JSONUtil.getString(msg, SecuConst.AUTH_CODE);

			Cache sessCache = CacheMgr.getCache(SecuConst.AUTH_CODE_CACHE);

			UserInfo ui = (UserInfo) sessCache.get(authCode).getObjectValue();

			if (ui == null) {

				KeyValue kvs = SecurityServiceMgr.getKVService();

				String uif = kvs.get(this.getKVAuthCodeName(authCode));

				if (uif == null)
					throw new SecurityAuthException("", ERR_MSG_INVALIDATE_USER_OR_AUTHCODE);

				SessionUserInfo sui = new SessionUserInfo(uif);
				ui = sui;
				sessCache.put(new Element(ui.getAuthCode(), ui));

			}

			if (!ui.getUserId().equals(userId) && !ui.getAuthCode().equals(authCode))
				throw new SecurityAuthException("", ERR_MSG_INVALIDATE_USER_OR_AUTHCODE);

			return JSONUtil.initSuccess().toString();

		} catch (SecurityAuthException e) {
			return JSONUtil.initFailed(e).toString();
		}

	}

	@POST
	@Path("/inqAuthCode")
	@Produces(MediaType.APPLICATION_JSON)
	public String inqAuthCode(@FormParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		try {

			JSONObject msg = JSONObject.fromObject(jsonMsg);

			KeyValue kvs = SecurityServiceMgr.getKVService();

			String inqAuthCode = JSONUtil.getString(msg, SecuConst.AUTH_INQ_CODE);

			String authCode = kvs.get(this.getKVInqAuthCodeName(inqAuthCode));

			if (authCode == null)
				throw new SecurityAuthException("", ERR_MSG_INVALIDATE_INQ_AUTHCODE);

			Cache sessCache = CacheMgr.getCache(SecuConst.AUTH_CODE_CACHE);

			UserInfo ui = (UserInfo) sessCache.get(authCode).getObjectValue();

			if (ui == null) {

				String uif = kvs.get(this.getKVAuthCodeName(authCode));

				if (uif == null)
					throw new SecurityAuthException("", ERR_MSG_INVALIDATE_INQ_AUTHCODE);

				SessionUserInfo sui = new SessionUserInfo(uif);
				ui = sui;
				sessCache.put(new Element(ui.getAuthCode(), ui));

			}

		 
			kvs.delete(this.getKVInqAuthCodeName(inqAuthCode));

			JSONObject jr = JSONUtil.initSuccess();
			jr.put(SecuConst.AUTH_CODE, ui.getAuthCode());
			jr.put(SecuConst.USER_ID, ui.getUserId());
			return jr.toString();

		} catch (SecurityAuthException e) {
			return JSONUtil.initFailed(e).toString();
		}

	}

	@POST
	@Path("/redirectPageLogin")
	@Produces(MediaType.APPLICATION_JSON)
	public void directPageLogin(@FormParam(SecuConst.USER_ID) String userId,
			@FormParam(SecuConst.USER_PW) String userPwd, @FormParam(SecuConst.AUTH_REDIRECT_URL) String redirectUrl,
			@Context HttpServletResponse response) throws IOException {

		JSONResult jr = new JSONResult(login(userId, userPwd, redirectUrl));
		if (jr.isSuccess()) {

			JSONObject msg = jr.getJSONObject();

			String url = redirectUrl + "?" + SecuConst.AUTH_INQ_CODE + "=" + msg.getString(SecuConst.AUTH_INQ_CODE);

			response.sendRedirect(url);

		} else {

			response.getWriter().write(jr.getErrorMessage());
		}
	}

	@POST
	@Path("/pageLogin")
	@Produces(MediaType.APPLICATION_JSON)
	public String pageLogin(@FormParam(SecuConst.USER_ID) String userId, @FormParam(SecuConst.USER_PW) String userPwd,
			@FormParam(SecuConst.AUTH_REDIRECT_URL) String redirectUrl) {
		return login(userId, userPwd, redirectUrl);
	}

	@POST
	@Path("/msgLogin")
	@Produces(MediaType.APPLICATION_JSON)
	public String msgLogin(@FormParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		JSONObject msg = JSONObject.fromObject(jsonMsg);

		String userId = JSONUtil.getString(msg, SecuConst.USER_ID);

		String userPwd = JSONUtil.getString(msg, SecuConst.USER_PW);

		String redirectUrl = JSONUtil.getString(msg, SecuConst.AUTH_REDIRECT_URL);

		return login(userId, userPwd, redirectUrl);

	}

	private String login(String userId, String userPwd, String redirectUrl) {

		try {

			UserInfo ui = SecurityServiceMgr.getUserInfoService().login(userId, userPwd);

			SessionUserInfo sui = new SessionUserInfo(ui);

			Cache sessCache = CacheMgr.getCache(SecuConst.AUTH_CODE_CACHE);

			sessCache.put(new Element(ui.getAuthCode(), sui));

			KeyValue kvs = SecurityServiceMgr.getKVService();

			kvs.set(this.getKVAuthCodeName(ui.getAuthCode()), sui.toJSONString(), 30 * 60);

			String inqCode = IDUtil.getRandomBase64UUID();

			kvs.set(this.getKVInqAuthCodeName(inqCode), ui.getAuthCode(), 30);

			JSONObject resMsg = JSONUtil.initSuccess();

			resMsg.put(SecuConst.AUTH_INQ_CODE, inqCode);

			resMsg.put(SecuConst.AUTH_REDIRECT_URL, redirectUrl);

			return resMsg.toString();

		} catch (SecurityAuthException e) {
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

class SessionUserInfo implements UserInfo {

	private String userId;
	private String userName;
	private String authCode;
	private String[] grpList;

	public SessionUserInfo(UserInfo ui) {
		this.userId = ui.getUserId();
		this.userName = ui.getUserName();
		this.authCode = ui.getAuthCode();
		this.grpList=ui.getUserGroups();
	}

	public SessionUserInfo(String jsonUI) {

		JSONObject jo = JSONObject.fromObject(jsonUI);
		this.userId = JSONUtil.getString(jo, SecuConst.USER_ID);
		this.userName = JSONUtil.getString(jo, SecuConst.USER_NAME);
		this.authCode = JSONUtil.getString(jo, SecuConst.AUTH_CODE);		
		JSONArray ja=JSONUtil.getJSONArray(jo, SecuConst.AUTH_USER_GROUPS);	
				
		if(ja!=null && ja.size()>0)
		this.grpList=(String[])ja.toArray(new String[0]);
	
	}

	public String toJSONString() {

		JSONObject jo = new JSONObject();
		jo.put(SecuConst.USER_ID, this.userId);
		jo.put(SecuConst.USER_NAME, this.userName);
		jo.put(SecuConst.AUTH_CODE, this.authCode);
		return jo.toString();

	}

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

	@Override
	public String[] getUserGroups() {
 		return this.grpList;
	}

}
