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

import static java.net.HttpURLConnection.HTTP_NOT_MODIFIED;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.encoding.EncodingHandler;
import io.undertow.util.HeaderValues;
import io.undertow.util.HttpString;
import org.apache.http.client.utils.DateUtils;
import org.hamcrest.core.StringStartsWith;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.url.http.utils.TestUtil;
import org.wildfly.url.http.utils.TestingServer;

/**
 * Test of compatibility with JDK implementation
 *
 * @author Jan Kalina <jkalina@redhat.com>
 */
@RunWith(TestingServer.class)
public class CompatibilityTest {

    @BeforeClass
    public static void setup() throws IOException {
        URL.setURLStreamHandlerFactory(new WildflyURLStreamHandlerFactory());

        TestingServer.setRootHandler(new EncodingHandler.Builder().build(null).wrap(new PathHandler()
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
                .addExactPath("get", exchange -> {
                    Date modified = new Date(10000);
                    exchange.getResponseHeaders().put(new HttpString("Last-Modified"), DateUtils.formatDate(modified));
                    String ifmod = exchange.getRequestHeaders().getFirst("If-Modified-Since");
                    if (ifmod != null) {
                        if (! modified.after(DateUtils.parseDate(ifmod))) {
                            exchange.setStatusCode(HTTP_NOT_MODIFIED);
                            return;
                        }
                    }
                    exchange.getResponseSender().send("Testing response");
                })
                .addExactPath("compressed", exchange -> {
                    exchange.getResponseSender().send("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                })
                .addExactPath("error", exchange -> {
                    exchange.setStatusCode(500);
                    exchange.setReasonPhrase("Testing error");
                    exchange.getResponseSender().send("Testing error output");
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
        ));
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
    public void testModifiedSince() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/get");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setIfModifiedSince(5);
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            Assert.assertEquals("Testing response", br.readLine());
        }
        Assert.assertEquals(10000, conn.getLastModified());
        conn.disconnect();

        HttpURLConnection conn2 = (HttpURLConnection) url.openConnection();
        conn2.setIfModifiedSince(10000);
        Assert.assertEquals(10000, conn2.getLastModified());
        try (InputStream is = conn2.getInputStream()) {
            Assert.assertEquals(-1, is.read());
        }
        conn2.disconnect();

        HttpURLConnection conn3 = (HttpURLConnection) url.openConnection();
        conn3.setIfModifiedSince(20000);
        Assert.assertEquals(10000, conn3.getLastModified());
        try (InputStream is = conn3.getInputStream()) {
            Assert.assertEquals(-1, is.read());
        }
        conn3.disconnect();
    }

    @Test
    public void testManualAuth() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/basic-auth");

        URLConnection conn = url.openConnection();
        String authorization = Base64.getEncoder().encodeToString("user:password".getBytes());
        conn.setRequestProperty("Authorization", "Basic " + authorization);

        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            Assert.assertEquals("Basic dXNlcjpwYXNzd29yZA==", br.readLine());
        }
    }

    @Test
    public void testErrorMessage() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/error");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        Assert.assertEquals(500, conn.getResponseCode());
        Assert.assertEquals("Testing error", conn.getResponseMessage());
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
            Assert.assertEquals("Testing error output", br.readLine());
        }
        try {
            conn.getInputStream();
            Assert.fail();
        } catch (IOException e) {
            Assert.assertEquals("Server returned HTTP response code: 500 for URL: " + url.toString(), e.getMessage());
        }
    }

    @Test
    public void testGzip() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerURL() + "/compressed");

        HttpURLConnection conn1 = (HttpURLConnection) url.openConnection();
        int uncompressedSize = conn1.getContentLength();
        String uncompressedMessage;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn1.getInputStream(), StandardCharsets.UTF_8))) {
            uncompressedMessage = br.readLine();
        }

        HttpURLConnection conn2 = (HttpURLConnection) url.openConnection();
        conn2.setRequestProperty("Accept-Encoding", "gzip");
        int compressedSize = conn2.getContentLength();
        String compressedMessage;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn2.getInputStream(), StandardCharsets.UTF_8))) {
            compressedMessage = br.readLine();
        }

        Assert.assertTrue(uncompressedSize == uncompressedMessage.length());
        Assert.assertTrue(compressedSize == compressedMessage.length());
        Assert.assertTrue(compressedSize < uncompressedSize);
    }

    @Test
    public void testSsl() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerSSLURL() + "/ssl-auth");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        conn.setSSLSocketFactory(TestUtil.getClientSslContextFactory().create().getSocketFactory());
        // keeping default HostnameVerifier

        conn.connect();
        Assert.assertThat(conn.getCipherSuite(), StringStartsWith.startsWith("TLS_"));
        Assert.assertEquals(1, conn.getLocalCertificates().length);
        Assert.assertEquals(1, conn.getServerCertificates().length);
        Assert.assertEquals("CN=localhost, OU=OU, O=Org, L=City, ST=State, C=GB", conn.getPeerPrincipal().toString());
        Assert.assertEquals("CN=Test Client, OU=OU, O=Org, L=City, ST=State, C=GB", conn.getLocalPrincipal().toString());

        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            Assert.assertEquals("(CN=Test Client, OU=OU, O=Org, L=City, ST=State, C=GB)", br.readLine());
        }
    }

    @Test
    public void testSslHostnameVerification() throws Exception {
        URL url = new URL(TestingServer.getDefaultServerSSLURL() + "/ssl-auth");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        conn.setSSLSocketFactory(TestUtil.getClientSslContextFactory().create().getSocketFactory());
        conn.setHostnameVerifier((s, sslSession) -> false);

        try {
            conn.connect();
            Assert.fail();
        } catch (SSLPeerUnverifiedException ignore) {}
    }
}
