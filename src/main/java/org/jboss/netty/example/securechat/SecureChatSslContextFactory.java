/*
 * Copyright 2009 Red Hat, Inc.
 *
 * Red Hat licenses this file to you under the Apache License, version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.jboss.netty.example.securechat;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.security.KeyStore;
import java.security.Security;

/**
 * Creates a bogus {@link javax.net.ssl.SSLContext}.  A client-side context created by this
 * factory accepts any certificate even if it is invalid.  A server-side context
 * created by this factory sends a bogus certificate defined in {@link org.jboss.netty.example.securechat.SecureChatKeyStore}.
 *
 * You will have to create your context differently in a real world application.
 *
 * @author The Netty Project (netty-dev@lists.jboss.org)
 * @author Trustin Lee (tlee@redhat.com)
 *
 * @version $Rev: 183008 $, $Date: 2008-11-18 20:44:38 -0500 (Tue, 18 Nov 2008) $
 */
public class SecureChatSslContextFactory {

    private static final String PROTOCOL = "TLS";

    private final SSLContext serverContext;
    private final SSLContext clientContext;

    private static final SecureChatSslContextFactory INSTANCE = new SecureChatSslContextFactory();

    public static final SecureChatSslContextFactory getInstance()
    {
        return INSTANCE;
    }

    public SecureChatSslContextFactory()
    {
        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        if (algorithm == null) {
            algorithm = "SunX509";
        }

        SSLContext tmpServerContext;
        SSLContext tmpClientContext;
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(SecureChatKeyStore.asInputStream(), SecureChatKeyStore.getKeyStorePassword());

            // Set up key manager factory to use our key store
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, SecureChatKeyStore.getCertificatePassword());

            // Initialize the SSLContext to work with our key managers.
            tmpServerContext = SSLContext.getInstance(PROTOCOL);
            tmpServerContext.init(kmf.getKeyManagers(), SecureChatTrustManagerFactory.getTrustManagers(), null);
        } catch (Exception e) {
            throw new Error("Failed to initialize the server-side SSLContext", e);
        }

        try {
            tmpClientContext = SSLContext.getInstance(PROTOCOL);
            tmpClientContext.init(null, SecureChatTrustManagerFactory.getTrustManagers(), null);
        } catch (Exception e) {
            throw new Error("Failed to initialize the client-side SSLContext", e);
        }

        serverContext = tmpServerContext;
        clientContext = tmpClientContext;
    }

    public SSLContext getServerContext() {
        return serverContext;
    }

    public SSLContext getClientContext() {
        return clientContext;
    }
}

