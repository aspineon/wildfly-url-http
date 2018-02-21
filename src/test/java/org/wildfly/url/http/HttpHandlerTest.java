package org.wildfly.url.http;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.util.ElytronAuthenticator;

public class HttpHandlerTest {

    @BeforeClass
    public static void init() {
        URL.setURLStreamHandlerFactory(new WildflyURLStreamHandlerFactory());
    }

    @Test
    public void testNoAuth() throws Exception {
        URL url = new URL("http://httpbin.org/");

        URLConnection conn = url.openConnection();
        conn.connect();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            System.out.println(br.readLine());
        }
    }

    @Test
    public void testHead() throws Exception {
        URL url = new URL("http://httpbin.org/redirect/3");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("HEAD");

        Assert.assertEquals(302, conn.getResponseCode());

        Assert.assertEquals(247, conn.getContentLength());
        Assert.assertEquals("/relative-redirect/2", conn.getHeaderField("Location"));

        Assert.assertNotNull(conn.getHeaderFieldKey(0));
        Assert.assertNotNull(conn.getHeaderField(0));

        Assert.assertEquals(null, conn.getHeaderFieldKey(100));
        Assert.assertEquals(null, conn.getHeaderField(100));

        for (Map.Entry<String,List<String>> entry : conn.getHeaderFields().entrySet()){
            System.out.println(entry.getKey());
            System.out.println(entry.getValue().get(0));
        }
    }

    @Test
    public void testRedirect() throws Exception {
        URL url = new URL("http://httpbin.org/redirect/3");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(true);
        //conn.connect();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            System.out.println(br.readLine());
            System.out.println(br.readLine());
            System.out.println(br.readLine());
            System.out.println(br.readLine());
        }
        //conn.disconnect();
    }

    @Test
    public void test() throws Exception {
        URL url = new URL("http://httpbin.org/basic-auth/user/passwd");

        AuthenticationContext.empty().with(MatchRule.ALL.matchPort(80).matchHost("httpbin.org").matchProtocol("http"),
                AuthenticationConfiguration.empty().useName("user").usePassword("passwd")).runExceptionAction(() -> {

            URLConnection conn = url.openConnection();
            conn.connect();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                System.out.println(br.readLine());
            }

            return null;
        });
    }

    @Test
    public void testCaching() throws Exception {
        Authenticator.setDefault(new ElytronAuthenticator());

        URL url2 = new URL("http://httpbin.org/basic-auth/user/passwd");
        url2.openConnection().setDefaultUseCaches(false);

        try {
            AuthenticationContext.empty().with(MatchRule.ALL /*.matchPort(80).matchHost("httpbin.org").matchProtocol("http")*/,
                    AuthenticationConfiguration.empty().useName("user").usePassword("passwd")).runExceptionAction(() -> {

                URL url = new URL("http://httpbin.org/basic-auth/user/passwd");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setUseCaches(false);
                conn.setInstanceFollowRedirects(false);
                conn.connect();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    System.out.println(br.readLine());
                    System.out.println(br.readLine());
                    System.out.println(br.readLine());
                    System.out.println(br.readLine());
                }

                return null;
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}