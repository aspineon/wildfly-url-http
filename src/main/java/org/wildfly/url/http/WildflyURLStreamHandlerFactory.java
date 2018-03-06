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

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

/**
 * Factory registering {@link URLStreamHandler} for HTTP/HTTPS
 *
 * @author Jan Kalina <jkalina@redhat.com>
 */
public class WildflyURLStreamHandlerFactory implements URLStreamHandlerFactory {

    private static URLStreamHandler httpHandler = new Handler(80);
    private static URLStreamHandler httpsHandler = new Handler(443);

    @Override
    public URLStreamHandler createURLStreamHandler(String protocol) {
        if (protocol.equalsIgnoreCase("http")) {
            return httpHandler;
        }
        if (protocol.equalsIgnoreCase("https")) {
            return httpsHandler;
        }
        return null;
    }

    private static class Handler extends URLStreamHandler {

        private final int defaultPort;

        Handler(int defaultPort) {
            this.defaultPort = defaultPort;
        }

        @Override
        protected int getDefaultPort() {
            return defaultPort;
        }

        @Override
        protected URLConnection openConnection(URL url) throws IOException {
            return new HttpClientURLConnection(url, null);
        }

        @Override
        protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
            return new HttpClientURLConnection(url, proxy);
        }
    }

}
