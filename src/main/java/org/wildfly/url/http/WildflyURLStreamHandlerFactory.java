package org.wildfly.url.http;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

import org.kohsuke.MetaInfServices;

@MetaInfServices(URLStreamHandlerFactory.class)
public class WildflyURLStreamHandlerFactory implements URLStreamHandlerFactory {

    private static URLStreamHandler httpHandler = new HttpURLStreamHandler();

    @Override
    public URLStreamHandler createURLStreamHandler(String protocol) {
        if (protocol.equalsIgnoreCase("http") || protocol.equalsIgnoreCase("https")) {
            return httpHandler;
        }
        return null;
    }

    static class HttpURLStreamHandler extends URLStreamHandler {

        @Override
        protected URLConnection openConnection(URL url) throws IOException {
            return new HttpClientURLConnection(url);
        }

    }

}
