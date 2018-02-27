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

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Provider providing Elytron credentials to the Apache HTTP client
 *
 * @author Jan Kalina <jkalina@redhat.com>
 */
class ElytronCredentialsProvider implements CredentialsProvider {

    static final ElytronCredentialsProvider INSTANCE = new ElytronCredentialsProvider();

    static final AuthenticationContextConfigurationClient client = doPrivileged(AuthenticationContextConfigurationClient.ACTION);

    @Override
    public Credentials getCredentials(AuthScope authscope) {
        final URI uri;
        final AuthenticationContext context = AuthenticationContext.captureCurrent();
        final AuthenticationConfiguration authenticationConfiguration;
        final HttpHost origin = authscope.getOrigin();
        final String protocol = origin != null ? origin.getSchemeName() : (authscope.getPort() == 443 ? "https" : "http");
        try {
            uri = new URI(protocol, null, authscope.getHost(), authscope.getPort(), null, null, null);
        } catch (URISyntaxException e) {
            log.tracef("URISyntaxException getting URI from the requesting AuthScope [%s]:", authscope.toString(), e);
            return null;
        }
        authenticationConfiguration = client.getAuthenticationConfiguration(uri, context);
        if (authenticationConfiguration == null) return null;
        final CallbackHandler callbackHandler = client.getCallbackHandler(authenticationConfiguration);
        final NameCallback nameCallback = new NameCallback("Username");
        final CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class);

        char[] password = null;
        try {
            callbackHandler.handle(new Callback[] { nameCallback, credentialCallback });
            final TwoWayPassword twoWayPassword = credentialCallback.applyToCredential(PasswordCredential.class, c -> c.getPassword().castAs(TwoWayPassword.class));
            if (twoWayPassword == null) {
                return null;
            }
            final PasswordFactory factory = PasswordFactory.getInstance(twoWayPassword.getAlgorithm(), client.getProviderSupplier(authenticationConfiguration));
            password = factory.getKeySpec(factory.translate(twoWayPassword), ClearPasswordSpec.class).getEncodedPassword();
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() == credentialCallback) {
                // try again with a password callback
                final PasswordCallback passwordCallback = new PasswordCallback("Password", false);
                try {
                    callbackHandler.handle(new Callback[] { nameCallback, passwordCallback });
                    password = passwordCallback.getPassword();
                } catch (IOException | UnsupportedCallbackException e1) {
                    log.trace("Error handling callback:", e1);
                    return null;
                }
            }
        } catch (IOException e){
            log.trace("IOException handling callback:", e);
            return null;
        } catch (NoSuchAlgorithmException e) {
            log.trace("NoSuchAlgorithmException getting PasswordFactory:", e);
            return null;
        } catch (InvalidKeySpecException e){
            log.trace("InvalidKeySpecException getting ClearPasswordSpec:", e);
            return null;
        } catch (InvalidKeyException e) {
            log.trace("InvalidKeyException getting ClearPasswordSpec:", e);
            return null;
        }
        final String name = nameCallback.getName();
        if (name == null || password == null) return null;
        return new UsernamePasswordCredentials(name, new String(password));
    }

    @Override
    public void setCredentials(AuthScope authscope, Credentials credentials) {
        throw new IllegalStateException("unsupported");
    }

    @Override
    public void clear() {
        throw new IllegalStateException("unsupported");
    }
}
