package org.wildfly.url.http;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
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
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

public class HttpClientURLConnection extends HttpURLConnection {

    private CloseableHttpClient client = null;
    private CloseableHttpResponse response;
    private ByteArrayOutputStream outputStream;


    HttpClientURLConnection(URL url) throws IOException {
        super(url);
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
        HttpUriRequest request;
        try {
            URI uri = getURL().toURI();
            request = getRequest(uri);
        } catch (URISyntaxException e) {
            throw new IOException("Unable to construct URI from URL", e);
        }

        if (outputStream != null) {
            if (request instanceof HttpEntityEnclosingRequestBase) { // POST or PUT
                ((HttpEntityEnclosingRequestBase) request).setEntity(new ByteArrayEntity(outputStream.toByteArray()));
            } else {
                throw new IllegalStateException("Used HTTP request method does not support OutputStream");
            }
        }

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(getConnectTimeout())
                .setSocketTimeout(getReadTimeout())
                .setRedirectsEnabled(getInstanceFollowRedirects())
                .build();

        client = HttpClientBuilder.create()
                .setDefaultCredentialsProvider(ElytronCredentialsProvider.INSTANCE)
                .setDefaultRequestConfig(config)
                .build();

        response = client.execute(request);
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
        return false;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (outputStream == null) {
            outputStream = new ByteArrayOutputStream();
        }
        return outputStream;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (response == null) {
            doRequest();
        }

        int responseCode = response.getStatusLine().getStatusCode();

        if (responseCode >= 400) {
            if (responseCode == 404 || responseCode == 410) {
                throw new FileNotFoundException(url.toString());
            } else {
                throw new IOException("Server returned HTTP response code: " + responseCode + " for URL: " + getURL().toString());
            }
        }

        HttpEntity entity = response.getEntity();
        if (entity == null) {
            throw new IOException("Used HTTP request method does not provide InputStream");
        }
        return entity.getContent();
    }

    @Override
    public int getResponseCode() throws IOException {
        if (response == null) {
            doRequest();
        }

        return response.getStatusLine().getStatusCode();
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

}
