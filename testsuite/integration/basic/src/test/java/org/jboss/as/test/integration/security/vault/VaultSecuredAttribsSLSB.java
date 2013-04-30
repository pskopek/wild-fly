/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013, Red Hat, Inc., and individual contributors
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

import java.nio.charset.Charset;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.util.Set;
import java.util.StringTokenizer;

import javax.ejb.EJBException;
import javax.ejb.Remote;
import javax.ejb.Stateless;

import org.jboss.logging.Logger;
import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultFactory;

/**
 * @author pskopek
 *
 */
@Stateless
@Remote(VaultAttributeReader.class)
public class VaultSecuredAttribsSLSB implements VaultAttributeReader {
    
    public static Logger log = Logger.getLogger(VaultSecuredAttribsSLSB.class); 
            
    static final Charset CHARSET = Charset.forName("UTF-8");
    
    public char[] getSecuredAttribute(String vaultedString) {
        try {
            SecurityVault vault;
            vault = AccessController.doPrivileged(new PrivilegedExceptionAction<SecurityVault>() {
                @Override
                public SecurityVault run() throws Exception {
                    return SecurityVaultFactory.get();
                }
            });           
            log.info("Got vault="+vault);
            log.info("vaultedString="+vaultedString);
            
            log.info("Vault keys dump:");
            Set<String> keys = vault.keyList(); 
            int i = 0;
            for (String key: keys) {
                log.info(i++ + ". " + key);
            }
            String[] token = tokens(vaultedString);
            return vault.retrieve(token[1], token[2], token[3].getBytes(CHARSET));
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }
    
    private String[] tokens(String vaultString) {
        StringTokenizer tokenizer = new StringTokenizer(vaultString, "::");
        int length = tokenizer.countTokens();
        String[] tokens = new String[length];

        int index = 0;
        while (tokenizer != null && tokenizer.hasMoreTokens()) {
            tokens[index++] = tokenizer.nextToken();
        }
        return tokens;
    }

    
}
