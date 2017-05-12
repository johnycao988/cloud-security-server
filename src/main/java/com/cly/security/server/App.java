package com.cly.security.server;

 

import javax.ws.rs.ApplicationPath;

import org.glassfish.jersey.server.ResourceConfig;

 

@ApplicationPath("/rest")
public class App extends ResourceConfig {

	
	
	public App() {
		init();
	}

	private void init() {

		packages("com.cly.security.server.rest.service");

	}

	

}