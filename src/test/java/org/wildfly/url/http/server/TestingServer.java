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

package org.wildfly.url.http.server;

import static org.xnio.Options.SSL_CLIENT_AUTH_MODE;
import static org.xnio.SslClientAuthMode.REQUESTED;

import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
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

import io.undertow.UndertowOptions;
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
import org.xnio.Options;
import org.xnio.StreamConnection;
import org.xnio.Xnio;
import org.xnio.XnioWorker;
import org.xnio.channels.AcceptingChannel;

/**
 * A class that starts a server before the test suite. By swapping out the root handler
 * tests can test various server functionality without continually starting and stopping the server.
 *
 * Based on DefaultServer from Undertow core tests.
 *
 * @author Jan Kalina
 * @author Stuart Douglas
 */
public class TestingServer extends BlockJUnit4ClassRunner {

    static final String DEFAULT = "default";
    private static final int PROXY_OFFSET = 1111;

    private static final ByteBufferPool BUFFER_POOL = new DefaultByteBufferPool(false, 100);
    private static final ByteBufferPool SSL_BUFFER_POOL = new DefaultByteBufferPool(false, 100);

    private static boolean first = true;
    private static OptionMap serverOptions;
    private static OpenListener openListener;
    private static ChannelListener acceptListener;
    private static XnioWorker worker;
    private static AcceptingChannel<? extends StreamConnection> server;
    private static AcceptingChannel<? extends StreamConnection> sslServer;
    private static Xnio xnio;

    private static final String SERVER_KEY_STORE = "server.keystore";
    private static final String SERVER_TRUST_STORE = "server.truststore";
    private static final char[] STORE_PASSWORD = "password".toCharArray();

    private static final boolean https = Boolean.getBoolean("test.https");

    private static final DelegatingHandler rootHandler = new DelegatingHandler();

    private static KeyStore loadKeyStore(final String name) throws IOException {
        final InputStream stream = TestingServer.class.getClassLoader().getResourceAsStream(name);
        if(stream == null) {
            throw new RuntimeException("Could not load keystore");
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

    public TestingServer(Class<?> klass) throws InitializationError {
        super(klass);
    }

    @Override
    public void run(final RunNotifier notifier) {
        runInternal(notifier);
        super.run(notifier);
    }

    private static void runInternal(final RunNotifier notifier) {
        if (first) {
            first = false;
            xnio = Xnio.getInstance("nio", TestingServer.class.getClassLoader());
            try {
                worker = xnio.createWorker(OptionMap.builder()
                        .set(Options.WORKER_IO_THREADS, 8)
                        .set(Options.CONNECTION_HIGH_WATER, 1000000)
                        .set(Options.CONNECTION_LOW_WATER, 1000000)
                        .set(Options.WORKER_TASK_CORE_THREADS, 30)
                        .set(Options.WORKER_TASK_MAX_THREADS, 30)
                        .set(Options.TCP_NODELAY, true)
                        .set(Options.CORK, true)
                        .getMap());

                serverOptions = OptionMap.builder()
                        .set(Options.TCP_NODELAY, true)
                        .set(Options.BACKLOG, 1000)
                        .set(Options.REUSE_ADDRESSES, true)
                        .set(Options.BALANCING_TOKENS, 1)
                        .set(Options.BALANCING_CONNECTIONS, 2)
                        .getMap();

                if (https) {
                    final SSLContext serverContext = createSSLContext(loadKeyStore(SERVER_KEY_STORE), loadKeyStore(SERVER_TRUST_STORE));
                    UndertowXnioSsl ssl = new UndertowXnioSsl(worker.getXnio(), OptionMap.EMPTY, SSL_BUFFER_POOL, serverContext);
                    openListener = new HttpOpenListener(
                            BUFFER_POOL, OptionMap.create(UndertowOptions.BUFFER_PIPELINED_DATA, true));
                    acceptListener = ChannelListeners.openListenerAdapter(openListener);
                    server = ssl.createSslConnectionServer(worker, new InetSocketAddress(getHostAddress("default"), 7777 + PROXY_OFFSET), acceptListener, serverOptions);
                    server.getAcceptSetter().set(acceptListener);
                    server.resumeAccepts();
                } else {
                    openListener = new HttpOpenListener(BUFFER_POOL, OptionMap.EMPTY);
                    acceptListener = ChannelListeners.openListenerAdapter(openListener);
                    server = worker.createStreamConnectionServer(new InetSocketAddress(Inet4Address.getByName(getHostAddress(DEFAULT)), getHostPort(DEFAULT)), acceptListener, serverOptions);
                }
                openListener.setRootHandler(rootHandler);
                server.resumeAccepts();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            notifier.addListener(new RunListener() {
                @Override
                public void testRunFinished(final Result result) throws Exception {
                    server.close();
                    stopSSLServer();
                    worker.shutdown();
                }
            });
        }
    }

    /**
     * Sets the root handler for the default web server
     *
     * @param handler The handler to use
     */
    public static void setRootHandler(HttpHandler handler) {
        rootHandler.next = handler;
    }

    /**
     * Start the SSL server using the default settings.
     * <p/>
     * The default settings initialise a server with a key for 'localhost' and a trust store containing the certificate of a
     * single client, the client authentication mode is set to 'REQUESTED' to optionally allow progression to CLIENT-CERT
     * authentication.
     */
    public static void startSSLServer() throws IOException {
        startSSLServer(getServerSslContext(), OptionMap.create(SSL_CLIENT_AUTH_MODE, REQUESTED));
    }

    public static SSLContext getServerSslContext() {
        try {
            return createSSLContext(loadKeyStore(SERVER_KEY_STORE), loadKeyStore(SERVER_TRUST_STORE));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Start the SSL server using the default ssl context and the provided option map
     * <p/>
     * The default settings initialise a server with a key for 'localhost' and a trust store containing the certificate of a
     * single client. Client cert mode is not set by default
     */
    public static void startSSLServer(OptionMap optionMap, ChannelListener openListener) throws IOException {
        SSLContext serverContext = createSSLContext(loadKeyStore(SERVER_KEY_STORE), loadKeyStore(SERVER_TRUST_STORE));
        startSSLServer(serverContext, optionMap, openListener);
    }

    /**
     * Start the SSL server using a custom SSLContext with additional options to pass to the JsseXnioSsl instance.
     *
     * @param context - The SSLContext to use for JsseXnioSsl initialisation.
     * @param options - Additional options to be passed to the JsseXnioSsl, this will be merged with the default options where
     *                applicable.
     */
    public static void startSSLServer(final SSLContext context, final OptionMap options) throws IOException {
        startSSLServer(context, options, acceptListener);
    }

    /**
     * Start the SSL server using a custom SSLContext with additional options to pass to the JsseXnioSsl instance.
     *
     * @param context - The SSLContext to use for JsseXnioSsl initialisation.
     * @param options - Additional options to be passed to the JsseXnioSsl, this will be merged with the default options where
     *                applicable.
     */
    public static void startSSLServer(final SSLContext context, final OptionMap options, ChannelListener openListener) throws IOException {
        startSSLServer(context, options, openListener, getHostSSLPort(DEFAULT));
    }


    /**
     * Start the SSL server using a custom SSLContext with additional options to pass to the JsseXnioSsl instance.
     *
     * @param context - The SSLContext to use for JsseXnioSsl initialisation.
     * @param options - Additional options to be passed to the JsseXnioSsl, this will be merged with the default options where
     *                applicable.
     */
    public static void startSSLServer(final SSLContext context, final OptionMap options, ChannelListener openListener, int port) throws IOException {
        OptionMap combined = OptionMap.builder().addAll(serverOptions).addAll(options)
                .set(Options.USE_DIRECT_BUFFERS, true)
                .getMap();

        UndertowXnioSsl ssl = new UndertowXnioSsl(worker.getXnio(), OptionMap.EMPTY, SSL_BUFFER_POOL, context);
        sslServer = ssl.createSslConnectionServer(worker, new InetSocketAddress(getHostAddress("default"), port), openListener, combined);
        sslServer.getAcceptSetter().set(openListener);
        sslServer.resumeAccepts();
    }

    /**
     * Stop any previously created SSL server - as this is for test clean up calling when no SSL server is running will not
     * cause an error.
     */
    public static void stopSSLServer() throws IOException {
        if (sslServer != null) {
            sslServer.close();
            sslServer = null;
        }
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

    public static OptionMap getUndertowOptions() {
        return openListener.getUndertowOptions();
    }

    public static void setUndertowOptions(final OptionMap options) {
        openListener.setUndertowOptions(OptionMap.builder().addAll(options).getMap());
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
