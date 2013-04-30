/*
 * JBoss, Home of Professional Open Source.
 * Copyright (c) 2012, Red Hat, Inc., and individual contributors
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

package org.jboss.as.test.integration.security.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.ADD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.CORE_SERVICE;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.NAME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.READ_ATTRIBUTE_OPERATION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.REMOVE;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.VAULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.VAULT_OPTIONS;

import org.jboss.as.test.integration.ejb.remote.security.EJBUtil;
import org.jboss.as.test.integration.security.common.Utils;

import java.io.File;
import java.nio.charset.Charset;
import java.util.Properties;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.commons.io.FileUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.client.OperationBuilder;
import org.jboss.as.ejb3.component.EJBUtilities;
import org.jboss.as.security.vault.VaultSession;
import org.jboss.dmr.ModelNode;
import org.jboss.ejb.client.ContextSelector;
import org.jboss.ejb.client.EJBClientConfiguration;
import org.jboss.ejb.client.EJBClientContext;
import org.jboss.ejb.client.PropertiesBasedEJBClientConfiguration;
import org.jboss.ejb.client.remoting.ConfigBasedEJBClientContextSelector;
import org.jboss.logging.Logger;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultFactory;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;


/**
 * MultipleVaultSecuredAttribsTestCase checks if vault created using VaultSession is holding
 * and able to access multiple newly created secured attributes.
 *
 * @author Peter Skopek (pskopek at redhat dot com)
 */
@RunWith(Arquillian.class)
@ServerSetup(MultipleVaultSecuredAttribsTestCase.MultipleVaultSecuredAttribsTestCaseSetup.class)
@RunAsClient
public class MultipleVaultSecuredAttribsTestCase {

    public static final Logger log = Logger.getLogger(MultipleVaultSecuredAttribsTestCase.class);
    
    static final Charset CHARSET = Charset.forName("UTF-8");

    public static final String VB1 = "vb1";
    public static final String ATTR_11 = "attr11";
    public static final String SEC_ATTR_11 = "secret11";
    public static final String ATTR_12 = "attr12";
    public static final String SEC_ATTR_12 = "secret12";
    public static final String VB2 = "vb2";
    public static final String ATTR_21 = "attr21";
    public static final String SEC_ATTR_21 = "secret21";
    public static final String ATTR_22 = "attr22";
    public static final String SEC_ATTR_22 = "secret22";


    /**
     * vault.keystore created using following command:
     * keytool -genkey -alias vault -keystore vault.keystore -keyalg RSA -keysize 1024 -storepass vault22 -keypass vault22 -dname "CN=Picketbox vault,OU=picketbox,O=JBoss,L=chicago,ST=il,C=us"
     */
    static class MultipleVaultSecuredAttribsTestCaseSetup implements ServerSetupTask {

        private ModelNode originalVault;
        private String encryptionDirectory = System.getProperty("java.io.tmpdir") + File.separator + "vault" + File.separator;

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {

            VaultSession nonInteractiveSession;
            ModelNode op;

            // copy keystore to temporary file
            FileUtils.copyURLToFile(MultipleVaultSecuredAttribsTestCase.class.getResource(KEYSTORE_FILENAME), keyStoreFile);

            // create new vault
            String keystoreURL = keyStoreFile.getAbsolutePath();
            String keystorePassword = "vault22";
            String salt = "12345678";
            int iterationCount = 55;

            // create security attributes
            nonInteractiveSession = new VaultSession(keystoreURL, keystorePassword, encryptionDirectory, salt, iterationCount);
            String vaultAlias = "vault";
            nonInteractiveSession.startVaultSession(vaultAlias);
            sharedKey11 = nonInteractiveSession.addSecuredAttribute(VB1, ATTR_11 , SEC_ATTR_11.toCharArray());
            sharedKey12 = nonInteractiveSession.addSecuredAttribute(VB1, ATTR_12 , SEC_ATTR_12.toCharArray());
            sharedKey21 = nonInteractiveSession.addSecuredAttribute(VB2, ATTR_21 , SEC_ATTR_21.toCharArray());
            sharedKey22 = nonInteractiveSession.addSecuredAttribute(VB2, ATTR_22 , SEC_ATTR_22.toCharArray());
            log.debug("sharedKey11 created ="+sharedKey11);
            log.debug("sharedKey12 created ="+sharedKey12);
            log.debug("sharedKey21 created ="+sharedKey21);
            log.debug("sharedKey22 created ="+sharedKey22);

            
            // clean temporary directory
            File datFile1 = new File(encryptionDirectory, ENC_DAT_FILE);
            if (datFile1.exists())
                datFile1.delete();
            File datFile2 = new File(encryptionDirectory, SHARED_DAT_FILE);
            if (datFile2.exists())
                datFile2.delete();

            // save original vault setting
            op = new ModelNode();
            op.get(OP).set(READ_ATTRIBUTE_OPERATION);
            op.get(OP_ADDR).add(CORE_SERVICE, VAULT);
            op.get(NAME).set(VAULT_OPTIONS);
            originalVault = (managementClient.getControllerClient().execute(new OperationBuilder(op).build())).get(RESULT);

            // remove original vault
            op = new ModelNode();
            op.get(OP).set(REMOVE);
            op.get(OP_ADDR).add(CORE_SERVICE, VAULT);
            managementClient.getControllerClient().execute(new OperationBuilder(op).build());

            // create new vault setting in standalone
            op = new ModelNode();
            op.get(OP).set(ADD);
            op.get(OP_ADDR).add(CORE_SERVICE, VAULT);
            ModelNode vaultOption = op.get(VAULT_OPTIONS);
            vaultOption.get("KEYSTORE_URL").set(keystoreURL);
            vaultOption.get("KEYSTORE_PASSWORD").set(nonInteractiveSession.getKeystoreMaskedPassword());
            vaultOption.get("KEYSTORE_ALIAS").set(vaultAlias);
            vaultOption.get("SALT").set(salt);
            vaultOption.get("ITERATION_COUNT").set(Integer.toString(iterationCount));
            vaultOption.get("ENC_FILE_DIR").set(encryptionDirectory);
            managementClient.getControllerClient().execute(new OperationBuilder(op).build());
            
            log.debug("vault configuration" + nonInteractiveSession.vaultConfiguration());

        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {

      /*      
            ModelNode op;

            // remove created vault
            op = new ModelNode();
            op.get(OP).set(REMOVE);
            op.get(OP_ADDR).add(CORE_SERVICE, VAULT);
            managementClient.getControllerClient().execute(new OperationBuilder(op).build());

            // set original vault
            if (originalVault.get("KEYSTORE_URL") != null) {
                op = new ModelNode();
                op.get(OP).set(ADD);
                op.get(OP_ADDR).add(CORE_SERVICE, VAULT);
                ModelNode vaultOption = op.get(VAULT_OPTIONS);
                vaultOption.get("KEYSTORE_URL").set(originalVault.get("KEYSTORE_URL"));
                vaultOption.get("KEYSTORE_PASSWORD").set(originalVault.get("KEYSTORE_PASSWORD"));
                vaultOption.get("KEYSTORE_ALIAS").set(originalVault.get("KEYSTORE_ALIAS"));
                vaultOption.get("SALT").set(originalVault.get("SALT"));
                vaultOption.get("ITERATION_COUNT").set(originalVault.get("ITERATION_COUNT"));
                vaultOption.get("ENC_FILE_DIR").set(originalVault.get("ENC_FILE_DIR"));
                managementClient.getControllerClient().execute(new OperationBuilder(op).build());
            }
*/
            // remove temporary files
          /*
            if (keyStoreFile.exists())
                keyStoreFile.delete();
            File datFile1 = new File(System.getProperty("java.io.tmpdir"), ENC_DAT_FILE);
            if (datFile1.exists())
                datFile1.delete();
            File datFile2 = new File(System.getProperty("java.io.tmpdir"), SHARED_DAT_FILE);
            if (datFile2.exists())
                datFile2.delete();
*/
        }

    }

    static final String KEYSTORE_FILENAME = "vault.keystore";
    static final String ENC_DAT_FILE = "ENC.dat";
    static final String SHARED_DAT_FILE = "Shared.dat";
    static final File keyStoreFile = new File(System.getProperty("java.io.tmpdir"), KEYSTORE_FILENAME);

    public static String sharedKey11;
    public static String sharedKey12;
    public static String sharedKey21;
    public static String sharedKey22;

    public static final String ARCHIVE_NAME = "vault_tester";
    
    @ArquillianResource
    private ManagementClient mgmtClient;
    
    @Deployment
    public static Archive<?> deploy() {
        JavaArchive jar = ShrinkWrap .create(JavaArchive.class, ARCHIVE_NAME + ".jar");
        Package pkg = MultipleVaultSecuredAttribsTestCase.class.getPackage();
        jar.addPackage(pkg);
        jar.addAsManifestResource(pkg, "jboss-deployment-structure.xml");
        return jar;
    }

    @ArquillianResource
    private InitialContext iniCtx;

    protected <T> T lookup(Class<T> beanType) throws NamingException {
        return beanType.cast(iniCtx.lookup("java:global/" + ARCHIVE_NAME + "/" + beanType.getSimpleName() + "!" + beanType.getName()));
    }
    
    /*
     * Tests that we have all secured attributes already in Vault.
     */
    @Test
    public void testMultipleSecuredAttributes() throws Exception {
        final Properties ejbClientConfiguration = EJBUtil.createEjbClientConfiguration(Utils.getHost(mgmtClient));
        EJBClientConfiguration cc = new PropertiesBasedEJBClientConfiguration(ejbClientConfiguration);
        final ContextSelector<EJBClientContext> selector = new ConfigBasedEJBClientContextSelector(cc);
        EJBClientContext.setSelector(selector);

        final VaultAttributeReader vaultReader = EJBUtil.lookupEJB(ARCHIVE_NAME, VaultSecuredAttribsSLSB.class, VaultAttributeReader.class);
        
        log.info("sharedKey11="+sharedKey11);
        char[] password11 = vaultReader.getSecuredAttribute(sharedKey11);
        Assert.assertArrayEquals(SEC_ATTR_11.toCharArray(), password11);
    }


}
