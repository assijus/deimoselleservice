package com.crivano.demoiselle.rest.server;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.crivano.blucservice.api.IBlueCrystal;
import com.crivano.swaggerservlet.SwaggerServlet;
import com.crivano.swaggerservlet.dependency.SwaggerHttpGetDependency;
import com.crivano.swaggerservlet.dependency.TestableDependency;

public class DemoiselleServlet extends SwaggerServlet {
	private static final long serialVersionUID = 1756711359239182178L;

	@Override
	public void initialize(ServletConfig config) throws ServletException {
		setAPI(IBlueCrystal.class);
		setActionPackage("com.crivano.demoiselle.rest.server");
		addPublicProperty("threadpool.size", "20");

		class HttpGetDependency extends TestableDependency {
			String testsite;

			HttpGetDependency(String service, String testsite, boolean partial, long msMin, long msMax) {
				super("network", service, partial, msMin, msMax);
				this.testsite = testsite;
			}

			@Override
			public String getUrl() {
				return testsite;
			}

			@Override
			public boolean test() throws Exception {
				final URL url = new URL(testsite);
				final URLConnection conn = url.openConnection();
				conn.connect();
				return true;
			}
		}

		addDependency(new SwaggerHttpGetDependency("network", "internet", "http://www.google.com", false, 0, 10000));

		addDependency(new SwaggerHttpGetDependency("network", "icpbrasil",
				"http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.der", false, 0, 10000));

		addDependency(new SwaggerHttpGetDependency("network", "accaixajus", "http://lcr.caixa.gov.br/accaixajusv2.crl",
				false, 0, 10000));
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		super.doPost(request, response);
	}
}
