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
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import io.undertow.server.handlers.PathHandler;
import io.undertow.util.HttpString;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.url.http.utils.TestUtil;
import org.wildfly.url.http.utils.TestingServer;

/**
 * Test of Elytron specific features - AuthenticationContext
 *
 * @author Jan Kalina <jkalina@redhat.com>
 */
@RunWith(TestingServer.class)
public class ElytronTest {

    @BeforeClass
    public static void setup() throws IOException {
        URL.setURLStreamHandlerFactory(new WildflyURLStreamHandlerFactory());

        TestingServer.setRootHandler(new PathHandler()
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
                .addExactPath("proxy-auth", exchange -> {
                    String authorization = exchange.getRequestHeaders().getFirst("Proxy-Authorization");
                    if (authorization == null) {
                        exchange.setStatusCode(407);
                        exchange.getResponseHeaders().put(new HttpString("Proxy-Authenticate"), "BASIC realm=realm2");
                        exchange.getResponseSender().send("Proxy Authentication Required");
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
     * Test BASIC authentication
     */
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
     * Test proxy authentication
     */
    @Test
    public void testProxyAuth() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/proxy-auth");
        Proxy proxy = new Proxy(Proxy.Type.HTTP, TestingServer.getDefaultServerSocketAddress());

        AuthenticationContext.empty().with(
                MatchRule.ALL.matchPort(url.getPort()).matchHost(url.getHost()).matchProtocol(url.getProtocol()),
                AuthenticationConfiguration.empty().useName("userproxy").usePassword("passwdproxy")
        ).runExceptionAction(() -> {
            URLConnection conn = url.openConnection(proxy);
            conn.connect();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                Assert.assertEquals("Basic dXNlcnByb3h5OnBhc3N3ZHByb3h5", br.readLine());
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
                TestUtil.getClientSslContextFactory()
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

}
