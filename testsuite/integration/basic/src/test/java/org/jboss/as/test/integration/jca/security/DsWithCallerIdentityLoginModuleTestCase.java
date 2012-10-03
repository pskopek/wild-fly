/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.test.integration.jca.security;

import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.test.integration.security.common.AbstractSecurityDomainSetup;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.fail;

/**
 * Data source with security domain and multiple users to get connection using null password.
 *
 * @author <a href="mailto:pskopek@redhat.com"> Peter Skopek</a>
 */
@RunWith(Arquillian.class)
@ServerSetup(DsWithCallerIdentityLoginModuleTestCase.CallerIdentityLMSetup.class)
public class DsWithCallerIdentityLoginModuleTestCase {

    static class CallerIdentityLMSetup extends AbstractLoginModuleSecurityDomainTestCaseSetup {

        @Override
        protected String getSecurityDomainName() {
            return "CallerIdentityDomain";
        }

        @Override
        protected String getLoginModuleName() {
            return "org.picketbox.datasource.security.CallerIdentityLoginModule";
        }

        @Override
        protected boolean isRequired() {
            return true;
        }

        @Override
        protected Map<String, String> getModuleOptions() {
            Map<String, String> moduleOptions = new HashMap<String, String>();
            moduleOptions.put("userName", "sa");
            moduleOptions.put("password", "sa");
            return moduleOptions;
        }
    }

    @Deployment
    public static Archive<?> deployment() {
        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, "single.jar").addClasses(
                DsWithCallerIdentityLoginModuleTestCase.class);
        jar.addClasses(AbstractLoginModuleSecurityDomainTestCaseSetup.class, AbstractSecurityDomainSetup.class);
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, "test.ear").addAsLibrary(jar)
                .addAsManifestResource("jca/security/data-sources/calleridentity-ds.xml", "calleridentity-ds.xml");

        return ear;
    }

    @ArquillianResource
    private InitialContext ctx;

    @Test
    public void nullPasswordTest() throws Exception {

        DataSource ds = (DataSource) ctx.lookup("java:jboss/datasources/calleridentityDS");
        Connection con = null;

        try {
            con = ds.getConnection("sa", "sa");
            assertNotNull(con);
        } finally {
            if (con != null)
                con.close();
        }

        con = null;
        try {
            con = ds.getConnection("sa", null);
            fail("Connection got unexpectedly");
        } catch (Exception e) {
            // intended
        } finally {
            if (con != null)
                con.close();
        }
    }

}
