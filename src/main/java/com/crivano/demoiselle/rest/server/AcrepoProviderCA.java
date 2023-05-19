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
package com.crivano.demoiselle.rest.server;

import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.extension.BasicCertificate;

import java.io.*;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Provides trusted Certificate Authority chain of the ICP-BRAZIL's digital
 * signature policies from Keystore (icpbrasil.jks) stored in resources library
 */

public class AcrepoProviderCA implements ProviderCA {
    static final Logger LOG = Logger.getLogger(AcrepoProviderCA.class.getName());
    static final String IGNORED_AC_SERPRO_V5 = "AC SERPRO-JUS v5";

    static {
        LOG.info("Carregando implementação própria de: " + AcrepoProviderCA.class.getName());
    }

    /**
     * read Certificate Authority chain from loaded keystore
     */
    @Override
    public Collection<X509Certificate> getCAs() {
        LOG.info("Carregando...");
        List<X509Certificate> result = new ArrayList<>();

        try (InputStream acStream = AcrepoProviderCA.class.getResourceAsStream("ACcompactadox.zip"); ZipInputStream zis = new ZipInputStream(acStream)) {
            if (Boolean.parseBoolean(DemoiselleServlet.getProp("acrepo.provider.download.inmemory"))) {
                LOG.info("- Loading certificates by ByteArrayOutputStream ...");
                addACsByByteArray(result, zis);
            } else {
                LOG.info("- Loading certificates by FileOutputStream ...");
                addAcsByFileSystem(result, zis);
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

    /**
     * write ACs to ByteArrayOutputStream from ZipInputStream
     */
    private void addACsByByteArray(List<X509Certificate> result, ZipInputStream zis) throws IOException {
        ZipEntry ze = zis.getNextEntry();
        for (; ze != null; ze = zis.getNextEntry()) {
            if (ze.isDirectory())
                continue;

            try (ByteArrayOutputStream outBuffer = new ByteArrayOutputStream()) {
                writeToBuffer(zis, outBuffer);
                BasicCertificate cert = new BasicCertificate(outBuffer.toByteArray());
                addACs(result, cert);
            } catch (Exception e) {
                LOG.log(Level.SEVERE, "- " + e.getMessage());
            }

            zis.closeEntry();
        }

    }

    /**
     * Create temp file write ACs to FileOutputStream from ZipInputStream and   addBasicCertificateFromFileAC
     */
    private void addAcsByFileSystem(List<X509Certificate> result, ZipInputStream zis) throws IOException {
        ZipEntry ze = zis.getNextEntry();
        for (; ze != null; ze = zis.getNextEntry()) {
            if (ze.isDirectory())
                continue;

            File tempFile = Files.createTempFile(ze.getName(), "").toFile();
            try {
                if (createFileAC(zis, tempFile)) addBasicCertificateFromFileAC(result, tempFile);
            } finally {
                if (tempFile.exists()) tempFile.delete();
            }
            zis.closeEntry();
        }
    }

    /**
     * Add BasicCertificate on provider list
     */
    private void addBasicCertificateFromFileAC(List<X509Certificate> result, File tempFile) {
        try (FileInputStream fileInputStream = new FileInputStream(tempFile)) {
            BasicCertificate cert = new BasicCertificate(fileInputStream);
            addACs(result, cert);
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "- " + e.getMessage());
        }
    }

    /**
     * Read temp File AC to FileBuffer
     */
    private Boolean createFileAC(ZipInputStream zis, File tempFile) {
        try (FileOutputStream outBuffer = new FileOutputStream(tempFile)) {
            writeToBuffer(zis, outBuffer);
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "- " + e.getMessage());
            return Boolean.FALSE;
        }

        return Boolean.TRUE;
    }

    /**
     * Add BasicCertificate on list or ignore if IGNORED_AC_SERPRO_V5
     */
    private void addACs(List<X509Certificate> result, BasicCertificate cert) {
        if (!cert.getName().contains(IGNORED_AC_SERPRO_V5)) {
            result.add(cert.getX509Certificate());
            LOG.info("- " + cert.getName());
        }
    }

    /**
     * Basic buffer writer
     */
    private void writeToBuffer(InputStream zis, OutputStream outBuffer) throws IOException {
        int len = 0;
        byte[] buffer = new byte[1024];
        while ((len = zis.read(buffer)) > 0) {
            outBuffer.write(buffer, 0, len);
        }
    }


}
