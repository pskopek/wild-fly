/*
 * JBoss, Home of Professional Open Source.
 * Copyright (c) 2011, Red Hat, Inc., and individual contributors
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

package org.jboss.as.test.integration.ejb.security.tx;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.as.test.integration.ejb.remote.common.EJBManagementUtil;
import org.jboss.as.test.integration.ejb.security.SecurityTest;
import org.jboss.as.test.shared.integration.ejb.security.Util;
import org.jboss.ejb.client.EJBClient;
import org.jboss.ejb.client.EJBClientTransactionContext;
import org.jboss.ejb.client.StatelessEJBLocator;
import org.jboss.logging.Logger;
import org.jboss.security.client.SecurityClient;
import org.jboss.security.client.SecurityClientFactory;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.*;
import org.junit.internal.runners.JUnit38ClassRunner;
import org.junit.runner.RunWith;

import javax.security.auth.login.LoginContext;
import javax.transaction.UserTransaction;

/**
 * Test to check that principal cannot be changed during course of transaction.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
@RunWith(Arquillian.class)
@RunAsClient
public class TxChangingPrincipalTestCase extends SecurityTest {

    private static final Logger log = Logger.getLogger(TxChangingPrincipalTestCase.class.getName());

    private static final String APP_NAME = "ejb-remote-client-tx-change-principal";
    private static final String MODULE_NAME = "ejb";

    private static final String MODULE = "txsectest";

    private static String nodeName;

    @Deployment(name = APP_NAME + ".ear", order = 1, testable = false)
    public static Archive<EnterpriseArchive> deployment() {

        // FIXME: change when there will be an option to deploy/call something before the first deployment
        try {
            // create required security domain
            SecurityTest.createSecurityDomain();
        } catch (Exception e) {
            log.warn("Problems during creation of security domain", e);
        }
        log.info("Security domain: ejb3-tests created");

        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, APP_NAME + ".ear");


        final JavaArchive jar = ShrinkWrap.create(JavaArchive.class, MODULE_NAME + ".jar")
              .addClass(TxBean.class)
              .addClass(TxRemote.class)
              .addAsResource("ejb3/security/users.properties", "users.properties")
              .addAsResource("ejb3/security/roles.properties", "roles.properties")
              .addAsManifestResource("ejb3/security/EMPTY_MANIFEST.MF", "MANIFEST.MF");

        ear.addAsModule(jar);

        return ear;
    }


    @BeforeClass
    public static void beforeTestClass() throws Exception {
        // the node name that the test methods can use
        nodeName = EJBManagementUtil.getNodeName("localhost", 9999);
        log.info("Using node name " + nodeName);
    }

    @AfterClass
    public static void tidyUpConfiguration() throws Exception {
        log.info("begin tidy up");
        SecurityTest.removeSecurityDomain();
    }

    @Before
    public void beforeTest() throws Exception {
        final EJBClientTransactionContext localUserTxContext = EJBClientTransactionContext.createLocal();
        // set the tx context
        EJBClientTransactionContext.setGlobalContext(localUserTxContext);

    }


    @Test
    public void testChangingPrincipal() throws Exception {

        final StatelessEJBLocator<TxRemote> txRemoteBeanLocator = new StatelessEJBLocator<TxRemote>(
              TxRemote.class, APP_NAME, MODULE_NAME, TxBean.class.getSimpleName(), "");
        final TxRemote txRemoteBean = EJBClient.createProxy(txRemoteBeanLocator);

        log.info("nodeName="+nodeName);

        final UserTransaction userTransaction = EJBClient.getUserTransaction(nodeName);

        log.info("userTransaction="+userTransaction);


        SecurityClient client = SecurityClientFactory.getSecurityClient();
        client.setSimple("user1", "password1");
        client.login();
        userTransaction.begin();


        boolean  first = txRemoteBean.firstMethod("user1");
        Assert.assertTrue(first);

        client.setSimple("user2", "password2");
        client.login();

        boolean  second = txRemoteBean.secondMethod("user2");
        Assert.assertFalse(second);

        userTransaction.commit();
        
    }



}
