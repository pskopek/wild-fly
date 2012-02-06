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

import org.jboss.ejb3.annotation.SecurityDomain;
import javax.annotation.Resource;
import javax.annotation.security.PermitAll;
import javax.ejb.*;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
@Stateless
@Remote(TxRemote.class)
@SecurityDomain("ejb3-tests")
public class TxBean implements TxRemote {

    @Resource
    private SessionContext ctx;



    @TransactionAttribute(TransactionAttributeType.MANDATORY)
    @PermitAll
    public boolean firstMethod(String supposedPrincipal) throws Exception {
        return check(supposedPrincipal);
    }

    @TransactionAttribute(TransactionAttributeType.MANDATORY)
    @PermitAll
    public boolean secondMethod(String supposedPrincipal) throws Exception {
        return check(supposedPrincipal);
    }


    public boolean check(String supposedPrincipal) {
        String currentPrincipal = ctx.getCallerPrincipal().getName();
        return supposedPrincipal.equals(currentPrincipal);
    }

}
