package com.cly.config.server;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class GetConfigFile
 */
@WebServlet(name = "ConfigServerServlet", urlPatterns = "/GetConfigFile", loadOnStartup = 1)
public class GetConfigFile extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final String AUTH_CODE = "CONFIG.SERVER.AUTH.CODE";
	private String authCode;
	private static Logger logger = Logger.getGlobal();

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public GetConfigFile() {
		super();
	}

	/**
	 * @see Servlet#init(ServletConfig)
	 */
	@Override
	public void init(ServletConfig config) throws ServletException {

		authCode = System.getProperty(AUTH_CODE, null);

		if (authCode == null) {
			logger.warning("Property:[" + AUTH_CODE + "] of Config Server is not set.");
		} else
			authCode = authCode.trim();

	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		String reqAuthCode = request.getParameter("AUTH_CODE");

		if (reqAuthCode != null)
			reqAuthCode = reqAuthCode.trim();

		String configFile = request.getParameter("CONFIG_FILE_NAME");
		
		if (authCode != null && !authCode.equals(reqAuthCode)) {
			throw new IOException("Invalide Auth code:" + reqAuthCode);
		}

		readConfigFile(configFile, response);

	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		response.getWriter().println("Cloud Config Server V1.0, relased on May 8, 2017. ");

	}

	protected void readConfigFile(String configFile, HttpServletResponse response)
			throws ServletException, IOException {

		try {

			try (FileInputStream fileInput = new FileInputStream(configFile);
					OutputStream out = response.getOutputStream()) {

				byte[] buffer = new byte[4098];

				int byteread = 0;

				while ((byteread = fileInput.read(buffer)) != -1) {

					out.write(buffer, 0, byteread);

				}
			}

		} catch (IOException ie) {
			logger.warning(ie.getMessage());
			throw ie;
		}
	}

}