package org.factor45.hotpotato.example;

import org.factor45.hotpotato.client.DefaultHttpClient;
import org.factor45.hotpotato.client.HttpClient;
import org.factor45.hotpotato.request.HttpRequestFuture;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpVersion;

public class Examples {

    public static void example1() {
        // Create & initialise the client
        HttpClient client = new DefaultHttpClient();
        client.init();

        // Setup the request
        HttpRequest request =
                new DefaultHttpRequest(HttpVersion.HTTP_1_0, HttpMethod.GET, "/");

        // Execute the request
        HttpRequestFuture future = client.execute("hotpotato.factor45.org", 80, request);
        future.awaitUninterruptibly();
        System.out.println(future);

        // Cleanup
        client.terminate();
    }

    public static void main(String[] args) {
        example1();
    }
}