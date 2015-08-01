package com.biasedbit.hotpotato.client;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

import java.io.Closeable;
import java.io.FileInputStream;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Before;
import org.junit.Test;

import com.biasedbit.hotpotato.response.BodyAsStringProcessor;
import com.biasedbit.hotpotato.request.HttpRequestFuture;
import com.biasedbit.hotpotato.client.DefaultHttpClient;

import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;

/**
 *
 */
public class HttpsTest {
    @Test
    public void testHttpsRequestSuccess() throws Exception
    {
        executeHttpsRequest("encrypted.google.com", "/", loadGoogleSslContext(), false);
    }

    @Test
    public void testHttpsRequestFailure() throws Exception
    {
        // This should fail since we don't have a cert for wellsfargo in our test trustStore...
        executeHttpsRequest("www.wellsfargo.com", "/", loadGoogleSslContext(), true);
    }

    private static SSLContext loadGoogleSslContext() throws Exception
    {
        String algorithm = "SunX509";
        String password  = "ez24get";

        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream keyAsStream = null;

        try
        {
            keyAsStream = new FileInputStream("src/test/resources/certs/encrypted.google.com.jks");
            keyStore.load(keyAsStream, password.toCharArray());
        }
        finally
        {
            closeQuietly(keyAsStream);
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);

        keyManagerFactory.init(keyStore, password.toCharArray());
        trustManagerFactory.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        return sslContext;
    }

    private static void closeQuietly(Closeable... closeables)
    {
        if (null != closeables)
        {
            for (Closeable closeable : closeables)
            {
                if (null != closeable)
                {
                    try
                    {
                        closeable.close();
                    }
                    catch (Exception e)
                    {
                        // Shhh...
                    }
                }
            }
        }
    }

    private static void executeHttpsRequest(final String host, final String resource, final SSLContext sslContext, final boolean shouldFail)
    throws Exception
    {
        DefaultHttpClient client = new DefaultHttpClient();
        client.setSSLContext(sslContext);
        client.setUseSsl(true);
        client.setUseNio(true);
        client.init();

        DefaultHttpRequest request =
            new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, resource);

        request.setHeader(HttpHeaders.Names.HOST, host);

        HttpRequestFuture future =
            client.execute(host, 443, request, new BodyAsStringProcessor()).await();

        if (shouldFail)
        {
            assertThat(future.getResponseStatusCode(), is(not(200)));
        }
        else
        {
            assertEquals(200, future.getResponseStatusCode());
        }

        assertTrue(true);
    }
}

