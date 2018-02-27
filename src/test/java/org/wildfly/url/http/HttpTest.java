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

package org.wildfly.url.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import io.undertow.server.handlers.PathHandler;
import io.undertow.util.HeaderValues;
import io.undertow.util.HttpString;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.url.http.server.TestingServer;

/**
 * @author Jan Kalina <jkalina@redhat.com>
 */
@RunWith(TestingServer.class)
public class HttpTest {

    @BeforeClass
    public static void setup() throws IOException {
        URL.setURLStreamHandlerFactory(new WildflyURLStreamHandlerFactory());

        TestingServer.setRootHandler(new PathHandler()
                .addExactPath("header", exchange -> {
                    Assert.assertEquals(0, exchange.getRequestHeaders().get("RequiredNoValueHeader", 0).length());
                    HeaderValues values = exchange.getRequestHeaders().get("TestingRequestHeader");
                    exchange.getResponseHeaders().putAll(new HttpString("TestingResponseHeader"), values);
                })
                .addExactPath("redirect", exchange -> {
                    int amount = Integer.parseInt(exchange.getQueryParameters().get("amount").getFirst());
                    if (amount > 0) {
                        String location = "/redirect?amount=" + (amount-1);
                        exchange.getResponseHeaders().put(new HttpString("Location"), location);
                        exchange.setStatusCode(302);
                        exchange.getResponseSender().send("Redirecting...");
                    } else {
                        exchange.getResponseSender().send("Finished");
                    }
                })
                .addExactPath("put", exchange -> {
                    exchange.getResponseSender().send("Received: " + exchange.getRequestContentLength());
                })
                .addExactPath("basic-auth", exchange -> {
                    String authorization = exchange.getRequestHeaders().getFirst("Authorization");
                    if (authorization == null) {
                        exchange.setStatusCode(401);
                        exchange.getResponseHeaders().put(new HttpString("WWW-Authenticate"), "BASIC realm=realm1");
                        exchange.getResponseSender().send("Unauthorized");
                    } else {
                        exchange.getResponseSender().send(authorization);
                    }
                })
                .addExactPath("ssl-auth", exchange -> {
                    Certificate[] certificates = exchange.getConnection().getSslSessionInfo().getPeerCertificates();
                    for (Certificate certificate : certificates) {
                        String name = ((X509Certificate)certificate).getSubjectDN().getName();
                        exchange.getResponseSender().send("(" + name + ")");
                    }
                })
        );
    }

    /**
     * Test sending HEAD request with request and response headers
     */
    @Test
    public void testHeader() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/header");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("RequiredNoValueHeader", null);
        conn.setRequestProperty("TestingRequestHeader", "TestingValue");
        conn.addRequestProperty("TestingRequestHeader", "TestingValue2");
        conn.setRequestMethod("HEAD");
        conn.connect();

        List<String> values = conn.getHeaderFields().get("TestingResponseHeader");
        Assert.assertTrue(values.contains("TestingValue"));
        Assert.assertTrue(values.contains("TestingValue2"));
    }

    /**
     * Test redirect (and query params)
     */
    @Test
    public void testRedirect() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/redirect?amount=2");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(true);

        Assert.assertEquals(200, conn.getResponseCode());
        Assert.assertEquals("OK", conn.getResponseMessage());
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            Assert.assertEquals("Finished", br.readLine());
        }
    }

    /**
     * Test disabled redirect
     */
    @Test
    public void testRedirectDisabled() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/redirect?amount=2");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);

        Assert.assertEquals(302, conn.getResponseCode());
        Assert.assertEquals("Found", conn.getResponseMessage());
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            Assert.assertEquals("Redirecting...", br.readLine());
        }
    }

    /**
     * Test content sending
     */
    @Test
    public void testPut() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/put");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("PUT");
        conn.setDoOutput(true);
        conn.getOutputStream().write(new byte[]{ 1, 2, 3 });

        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            Assert.assertEquals("Received: 3", br.readLine());
        }
    }

    @Test
    public void testBasicAuth() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/basic-auth");

        AuthenticationContext.empty().with(
                MatchRule.ALL.matchPort(url.getPort()).matchHost(url.getHost()).matchProtocol(url.getProtocol()),
                AuthenticationConfiguration.empty().useName("user1").usePassword("passwd1")
        ).runExceptionAction(() -> {
            URLConnection conn = url.openConnection();
            conn.connect();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                Assert.assertEquals("Basic dXNlcjE6cGFzc3dkMQ==", br.readLine());
            }
            return null;
        });

        AuthenticationContext.empty().with(
                MatchRule.ALL.matchPort(url.getPort()).matchHost(url.getHost()).matchProtocol(url.getProtocol()),
                AuthenticationConfiguration.empty().useName("user2").usePassword("passwd2")
        ).runExceptionAction(() -> {
            URLConnection conn = url.openConnection();
            conn.connect();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                Assert.assertEquals("Basic dXNlcjI6cGFzc3dkMg==", br.readLine());
            }
            return null;
        });
    }

    /**
     * Test sending HEAD request with request and response headers
     */
    @Test
    public void testSsl() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerSSLURL() + "/ssl-auth");

        AuthenticationContext.empty().withSsl(
                MatchRule.ALL.matchPort(url.getPort()).matchHost(url.getHost()).matchProtocol(url.getProtocol()),
                getClientSslContext()
        ).runExceptionAction(() -> {

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.connect();

            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                Assert.assertEquals("(CN=Test Client, OU=OU, O=Org, L=City, ST=State, C=GB)", sb.toString());
            }
            return null;
        });
    }

    private SecurityFactory<SSLContext> getClientSslContext() throws Exception {
        X509TrustManager trustManager = null;
        X509ExtendedKeyManager keyManager = null;

        KeyStore truststore = KeyStore.getInstance("JKS");
        truststore.load(HttpTest.class.getClassLoader().getResourceAsStream("client.truststore"), "password".toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(truststore);
        for (TrustManager tm : trustManagerFactory.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                trustManager = (X509TrustManager) tm;
            }
        }
        if (trustManager == null) throw new IllegalStateException("No X509TrustManager provided");

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(HttpTest.class.getClassLoader().getResourceAsStream("client.keystore"), "password".toCharArray());
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
