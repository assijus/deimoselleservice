package com.crivano.demoiselle.rest.server;

import junit.framework.TestCase;
import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.mockito.Mockito;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;


public class DemoiselleServletTest extends TestCase {


    public void testAddACsByByteArray() throws ServletException {
        DemoiselleServlet demoiselleServlet = new DemoiselleServlet();
        ServletConfig sc = Mockito.mock(ServletConfig.class);
        demoiselleServlet.initialize(sc);

        ProviderCA providerCA = new AcrepoProviderCA();

        assertNotNull(providerCA.getCAs());
    }


    public void testAddACsByFileSystem() throws ServletException {
        DemoiselleServlet demoiselleServlet = new DemoiselleServlet();
        ServletConfig sc = Mockito.mock(ServletConfig.class);
        demoiselleServlet.initialize(sc);
        demoiselleServlet.setProperty("acrepo.provider.download.inmemory", "false");

        ProviderCA providerCA = new AcrepoProviderCA();

        assertNotNull(providerCA.getCAs());
    }

}