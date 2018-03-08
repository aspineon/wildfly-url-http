/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.url.http.utils;

import static org.xnio.Options.SSL_CLIENT_AUTH_MODE;
import static org.xnio.SslClientAuthMode.REQUESTED;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import io.undertow.connector.ByteBufferPool;
import io.undertow.protocols.ssl.UndertowXnioSsl;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.OpenListener;
import io.undertow.server.protocol.http.HttpOpenListener;
import io.undertow.util.NetworkUtils;
import org.junit.runner.Result;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;
import org.xnio.ChannelListener;
import org.xnio.ChannelListeners;
import org.xnio.IoUtils;
import org.xnio.OptionMap;
import org.xnio.StreamConnection;
import org.xnio.Xnio;
import org.xnio.XnioWorker;
import org.xnio.channels.AcceptingChannel;

/**
 * A class that starts a server before the test suite. By swapping out the root handler
 * tests can test various server functionality without continually starting and stopping the server.
 *
 * @author Jan Kalina
 */
public class TestingServer extends BlockJUnit4ClassRunner {

    private static final String DEFAULT = "default";

    private static final ByteBufferPool BUFFER_POOL = new DefaultByteBufferPool(false, 100);

    private static boolean first = true;
    private static XnioWorker worker;
    private static AcceptingChannel<? extends StreamConnection> server;
    private static AcceptingChannel<? extends StreamConnection> sslServer;

    private static final String SERVER_KEY_STORE = "server.keystore";
    private static final String SERVER_TRUST_STORE = "server.truststore";
    private static final char[] STORE_PASSWORD = "password".toCharArray();

    private static final DelegatingHandler rootHandler = new DelegatingHandler();

    private static KeyStore loadKeyStore(final String name) throws IOException {
        final InputStream stream = TestingServer.class.getClassLoader().getResourceAsStream(name);
        if(stream == null) {
            throw new RuntimeException(String.format("Could not load KeyStore %s", name));
        }
        try {
            KeyStore loadedKeystore = KeyStore.getInstance("JKS");
            loadedKeystore.load(stream, STORE_PASSWORD);

            return loadedKeystore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new IOException(String.format("Unable to load KeyStore %s", name), e);
        } finally {
            IoUtils.safeClose(stream);
        }
    }

    private static SSLContext createSSLContext(final KeyStore keyStore, final KeyStore trustStore) throws IOException {
        KeyManager[] keyManagers;
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, STORE_PASSWORD);
            keyManagers = keyManagerFactory.getKeyManagers();
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            throw new IOException("Unable to initialise KeyManager[]", e);
        }

        TrustManager[] trustManagers = null;
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            trustManagers = trustManagerFactory.getTrustManagers();
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IOException("Unable to initialise TrustManager[]", e);
        }

        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IOException("Unable to create and initialise the SSLContext", e);
        }

        return sslContext;
    }

    /**
     * @return The base URL that can be used to make HTTP connections to this server
     */
    public static String getDefaultServerURL() {
        return "http://" + NetworkUtils.formatPossibleIpv6Address(getHostAddress(DEFAULT)) + ":" + getHostPort(DEFAULT);
    }

    /**
     * @return The base URL that can be used to make HTTPS connections to this server
     */
    public static String getDefaultServerSSLURL() {
        return "https://" + NetworkUtils.formatPossibleIpv6Address(getHostAddress(DEFAULT)) + ":" + getHostSSLPort(DEFAULT);
    }

    public static InetSocketAddress getDefaultServerSocketAddress() {
        return new InetSocketAddress(getHostAddress(DEFAULT), getHostPort(DEFAULT));
    }

    public TestingServer(Class<?> klass) throws InitializationError {
        super(klass);
    }

    @Override
    public void run(final RunNotifier notifier) {
        if (first) {
            first = false;
            Xnio xnio = Xnio.getInstance("nio", TestingServer.class.getClassLoader());
            try {
                worker = xnio.createWorker(OptionMap.EMPTY);
                OpenListener openListener = new HttpOpenListener(BUFFER_POOL, OptionMap.EMPTY);
                openListener.setRootHandler(rootHandler);
                ChannelListener acceptListener = ChannelListeners.openListenerAdapter(openListener);

                server = worker.createStreamConnectionServer(new InetSocketAddress(getHostAddress(DEFAULT), getHostPort(DEFAULT)), acceptListener, OptionMap.EMPTY);
                server.resumeAccepts();

                SSLContext serverContext = createSSLContext(loadKeyStore(SERVER_KEY_STORE), loadKeyStore(SERVER_TRUST_STORE));
                UndertowXnioSsl ssl = new UndertowXnioSsl(worker.getXnio(), OptionMap.EMPTY, serverContext);
                OptionMap sslOptions = OptionMap.create(SSL_CLIENT_AUTH_MODE, REQUESTED);
                sslServer = ssl.createSslConnectionServer(worker, new InetSocketAddress(getHostAddress(DEFAULT), getHostSSLPort(DEFAULT)), acceptListener, sslOptions);
                sslServer.resumeAccepts();

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            notifier.addListener(new RunListener() {
                @Override
                public void testRunFinished(final Result result) throws Exception {
                    server.close();
                    sslServer.close();
                    worker.shutdown();
                }
            });
        }
        super.run(notifier);
    }

    /**
     * Sets the root handler for the default web server
     *
     * @param handler The handler to use
     */
    public static void setRootHandler(HttpHandler handler) {
        rootHandler.next = handler;
    }

    public static String getHostAddress(String serverName) {
        return System.getProperty(serverName + ".server.address", "localhost");
    }

    public static int getHostPort(String serverName) {
        return Integer.getInteger(serverName + ".server.port", 7777);
    }

    public static int getHostSSLPort(String serverName) {
        return Integer.getInteger(serverName + ".server.sslPort", 7778);
    }

    /**
     * The root handler allowing to change rootHandler during tests.
     */
    private static final class DelegatingHandler implements HttpHandler {

        volatile HttpHandler next;

        @Override
        public void handleRequest(HttpServerExchange exchange) throws Exception {
            next.handleRequest(exchange);
        }
    }
}
