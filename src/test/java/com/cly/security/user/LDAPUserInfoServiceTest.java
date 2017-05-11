package com.cly.security.user;

 
import org.junit.Test;

import com.cly.comm.client.http.HttpClient;
import com.cly.comm.client.http.HttpRequestParam;

import net.sf.json.JSONObject;

public class LDAPUserInfoServiceTest {

	@Test
	public void testDoPost() {

		try {

			String url = "http://localhost:8080/cloud-security-server/rest/user/login";

			HttpRequestParam rp = new HttpRequestParam();


			JSONObject msg = new JSONObject();

			msg.put(UserConst.USER_ID, "johnny.cao");
			msg.put(UserConst.USER_PW, "ldap123");
			rp.addParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME, msg.toString()); 
			 
			String res = HttpClient.request(url, HttpClient.REQUEST_METHOD_POST, rp);
			System.out.println("response:" + res);

		} catch (Exception e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
		}

	}

}
