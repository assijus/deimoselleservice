/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */
package com.crivano.deimoselle.rest.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.util.MessagesBundle;

/**
 * Provides trusted Certificate Authority chain of the ICP-BRAZIL's digital
 * signature policies from Keystore (icpbrasil.jks) stored in resources library
 */
public class AcrepoProviderCA implements ProviderCA {
	static final Logger LOG = Logger.getLogger(AcrepoProviderCA.class.getName());

	static {
		LOG.info("Carregando implementação própria de: " + AcrepoProviderCA.class.getName());
	}

	private static MessagesBundle chainMessagesBundle = new MessagesBundle();

	/**
	 * read Certificate Authority chain from loaded keystore
	 */
	@Override
	public Collection<X509Certificate> getCAs() {
		LOG.info("Carregando...");
		List<X509Certificate> result = new ArrayList<>();

		InputStream myIs = AcrepoProviderCA.class.getResourceAsStream("ACcompactadox.zip");

		ZipInputStream zis = new ZipInputStream(myIs);

		ZipEntry ze;
		try {
			ze = zis.getNextEntry();
			long totalLen = 0l;
			for (; ze != null; ze = zis.getNextEntry()) {
				if (ze.isDirectory())
					continue;
				try {
					ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
					totalLen += ze.getSize();
					int len = 0;
					byte[] buffer = new byte[1024];

					while ((len = zis.read(buffer)) > 0) {
						outBuffer.write(buffer, 0, len);
					}
					BasicCertificate cert = new BasicCertificate(outBuffer.toByteArray());
					if (cert.getName().contains("AC SERPRO-JUS v5"))
						continue;
					result.add(cert.getX509Certificate());
					LOG.info("- " + cert.getName());
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				zis.closeEntry();
			}
		} catch (Exception e) {
			throw new RuntimeException("erro carregando certificados", e);
		}
		return result;
	}

	/**
	 * This provider Name
	 */
	@Override
	public String getName() {
		return AcrepoProviderCA.class.getSimpleName();
	}
}
