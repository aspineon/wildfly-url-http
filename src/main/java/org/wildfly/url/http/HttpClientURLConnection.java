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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpOptions;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpTrace;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.DateUtils;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.client.AuthenticationContext;

/**
 * {@link URLConnection} handling HTTP/HTTPS using Apache HTTP client
 *
 * @author Jan Kalina <jkalina@redhat.com>
 */
class HttpClientURLConnection extends HttpsURLConnection {

    private final HttpHost proxy;
    private CloseableHttpClient client;
    private CloseableHttpResponse response;
    private ByteArrayOutputStream outputStream;
    private SSLSession sslSession;

    HttpClientURLConnection(URL url, Proxy proxy) throws IOException {
        super(url);
        this.proxy = convertProxy(proxy);
    }

    private HttpHost convertProxy(Proxy proxy) throws UnknownHostException {
        if (proxy == null || proxy.type() == Proxy.Type.DIRECT) {
            return null;
        }
        if (proxy.type() == Proxy.Type.HTTP) {
            if (proxy.address() instanceof InetSocketAddress) {
                InetSocketAddress address = (InetSocketAddress) proxy.address();
                if (address.getAddress() == null) {
                    throw new UnknownHostException("Unable resolve proxy address");
                }
                return new HttpHost(address.getAddress(), address.getPort(), "http");
            }
        }
        throw new UnsupportedOperationException("Unsupported type of proxy.");
    }

    private HttpUriRequest getRequest(URI uri) {
        switch (getRequestMethod()) {
            case "GET": return new HttpGet(uri);
            case "POST": return new HttpPost(uri);
            case "HEAD": return new HttpHead(uri);
            case "OPTIONS": return new HttpOptions(uri);
            case "PUT": return new HttpPut(uri);
            case "DELETE": return new HttpDelete(uri);
            case "TRACE": return new HttpTrace(uri);
            default: throw new IllegalStateException("Unsupported HTTP request method");
        }
    }

    private void doRequest() throws IOException {
        URI uri;
        try {
            uri = getURL().toURI();
        } catch (URISyntaxException e) {
            throw new IOException("Unable to construct URI from URL", e);
        }
        HttpUriRequest request = getRequest(uri);

        // request headers
        if (getIfModifiedSince() != 0) {
            request.setHeader("If-Modified-Since", DateUtils.formatDate(new Date(getIfModifiedSince())));
        }
        for (Map.Entry<String, List<String>> prop : getRequestProperties().entrySet()) {
            for (String value : prop.getValue()) {
                request.addHeader(prop.getKey(), value);
            }
        }

        if (outputStream != null) {
            if (request instanceof HttpEntityEnclosingRequestBase) { // POST or PUT
                request.removeHeaders(HTTP.CONTENT_LEN); // would be in collision with set entity
                request.removeHeaders(HTTP.TRANSFER_ENCODING);
                ((HttpEntityEnclosingRequestBase) request).setEntity(new ByteArrayEntity(outputStream.toByteArray()));
            } else {
                throw new IllegalStateException("Used HTTP request method does not support OutputStream");
            }
        }

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(getConnectTimeout())
                .setSocketTimeout(getReadTimeout())
                .setRedirectsEnabled(getInstanceFollowRedirects())
                .setProxy(proxy)
                .build();

        HttpClientBuilder builder = HttpClientBuilder.create()
                .setDefaultCredentialsProvider(ElytronCredentialsProvider.INSTANCE)
                .setDefaultRequestConfig(config)
                .disableContentCompression();

        if (uri.getScheme().equalsIgnoreCase("https")) {
            SSLSocketFactory socketFactory = getSSLSocketFactory();

            if (socketFactory != getDefaultSSLSocketFactory()) {
                HostnameVerifier hostnameVerifier = getHostnameVerifier();
                if (hostnameVerifier == getDefaultHostnameVerifier()) {
                    hostnameVerifier = null; // use HttpClient default
                }
                builder.setSSLSocketFactory(new SSLConnectionSocketFactory(socketFactory, hostnameVerifier));
            } else {
                try {
                    SecurityFactory<SSLContext> sslContextFactory = ElytronCredentialsProvider.client
                            .getSSLContextFactory(uri, AuthenticationContext.captureCurrent(), null, null);
                    builder.setSSLContext(sslContextFactory.create());
                } catch (GeneralSecurityException e) {
                    throw new IOException(e);
                }
            }

            client = builder.build();
            HttpContext context = new BasicHttpContext();
            response = client.execute(request, context);

            ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection)
                    context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
            sslSession = routedConnection.getSSLSession();
        } else {
            client = builder.build();
            response = client.execute(request);
        }
    }

    private void ensureResponse() {
        if (response == null) {
            try {
                doRequest();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public void connect() throws IOException {
        doRequest();
    }

    @Override
    public void disconnect() {
        if (client != null) {
            try {
                client.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public boolean usingProxy() {
        return proxy != null;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (outputStream == null) {
            outputStream = new ByteArrayOutputStream();
        }
        return outputStream;
    }

    @Override
    public void setFixedLengthStreamingMode(int contentLength) {
        if (outputStream == null) {
            outputStream = new ByteArrayOutputStream(contentLength);
        }
    }

    @Override
    public void setFixedLengthStreamingMode(long contentLength) {
        if (contentLength > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Too long content length");
        }
        if (outputStream == null) {
            outputStream = new ByteArrayOutputStream((int) contentLength);
        }
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (response == null) {
            doRequest();
        }

        int responseCode = response.getStatusLine().getStatusCode();

        if (responseCode >= 400) {
            if (responseCode == HTTP_NOT_FOUND || responseCode == HTTP_GONE) {
                throw new FileNotFoundException(url.toString());
            } else {
                throw new IOException("Server returned HTTP response code: " + responseCode + " for URL: " + getURL().toString());
            }
        }

        if (responseCode == HTTP_NOT_MODIFIED) {
            return new ByteArrayInputStream(new byte[0]);
        }

        HttpEntity entity = response.getEntity();
        if (entity == null) {
            throw new IOException("Used HTTP request method does not provide InputStream");
        }
        return entity.getContent();
    }

    @Override
    public InputStream getErrorStream() {
        if (response == null || response.getStatusLine().getStatusCode() < 400) {
            return null;
        }
        HttpEntity entity = response.getEntity();
        if (entity != null) {
            try {
                return entity.getContent();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return null;
    }

    @Override
    public int getResponseCode() throws IOException {
        if (response == null) {
            doRequest();
        }

        return response.getStatusLine().getStatusCode();
    }

    @Override
    public String getResponseMessage() throws IOException {
        if (response == null) {
            doRequest();
        }

        return response.getStatusLine().getReasonPhrase();
    }

    @Override
    public String getHeaderField(String name) {
        ensureResponse();
        Header header = response.getLastHeader(name);
        if (header == null) return null;
        return header.getValue();
    }

    @Override
    public Map<String, List<String>> getHeaderFields() {
        ensureResponse();
        Map<String, List<String>> output = new HashMap<>();
        for (Header header : response.getAllHeaders()) {
            String name = header.getName();
            if (! output.containsKey(name)) {
                output.put(name, new ArrayList<>(1));
            }
            output.get(name).add(header.getValue());
        }
        return Collections.unmodifiableMap(output);
    }

    @Override
    public String getHeaderFieldKey(int n) {
        ensureResponse();
        Header[] headers = response.getAllHeaders();
        if (0 > n || n >= headers.length) return null;
        return headers[n].getName();
    }

    @Override
    public String getHeaderField(int n) {
        ensureResponse();
        Header[] headers = response.getAllHeaders();
        if (0 > n || n >= headers.length) return null;
        return headers[n].getValue();
    }

    @Override
    public String getCipherSuite() {
        if (response == null) {
            throw new IllegalStateException("connection not yet open");
        }
        if (sslSession == null) {
            throw new UnsupportedOperationException("not a SSL connection");
        }
        return sslSession.getCipherSuite();
    }

    @Override
    public Certificate[] getLocalCertificates() {
        if (response == null) {
            throw new IllegalStateException("connection not yet open");
        }
        if (sslSession == null) {
            throw new UnsupportedOperationException("not a SSL connection");
        }
        return sslSession.getLocalCertificates();
    }

    @Override
    public Certificate[] getServerCertificates() throws SSLPeerUnverifiedException {
        if (response == null) {
            throw new IllegalStateException("connection not yet open");
        }
        if (sslSession == null) {
            throw new UnsupportedOperationException("not a SSL connection");
        }
        return sslSession.getPeerCertificates();
    }
}
