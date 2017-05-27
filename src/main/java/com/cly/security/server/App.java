package com.cly.security.server;

import java.io.IOException;

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig; 
 

@ApplicationPath("/rest")
public class App extends ResourceConfig {

		
	public App() throws IOException {
		init();
	}

	private void init() throws IOException {

		packages("com.cly.security.server.rest.service"); 
		
		SecurityServiceMgr.init(); 
		
	}

	

}