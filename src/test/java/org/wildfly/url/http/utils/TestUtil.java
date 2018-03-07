/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.url.http.utils;

import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.url.http.CompatibilityTest;

/**
 * Helper utils for tests
 *
 * @author Jan Kalina <jkalina@redhat.com>
 */
public class TestUtil {

    public static SecurityFactory<SSLContext> getClientSslContextFactory() throws Exception {
        X509TrustManager trustManager = null;
        X509ExtendedKeyManager keyManager = null;

        KeyStore truststore = KeyStore.getInstance("JKS");
        truststore.load(CompatibilityTest.class.getClassLoader().getResourceAsStream("client.truststore"), "password".toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(truststore);
        for (TrustManager tm : trustManagerFactory.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                trustManager = (X509TrustManager) tm;
            }
        }
        if (trustManager == null) throw new IllegalStateException("No X509TrustManager provided");

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(CompatibilityTest.class.getClassLoader().getResourceAsStream("client.keystore"), "password".toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keystore, "password".toCharArray());
        for (KeyManager km : keyManagerFactory.getKeyManagers()) {
            if (km instanceof X509ExtendedKeyManager) {
                keyManager = (X509ExtendedKeyManager) km;
            }
        }
        if (keyManager == null) throw new IllegalStateException("No X509ExtendedKeyManager provided");

        SSLContextBuilder builder = new SSLContextBuilder();
        builder.setClientMode(true);
        builder.setTrustManager(trustManager);
        builder.setKeyManager(keyManager);
        return builder.build();
    }

}
