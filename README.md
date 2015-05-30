# NIO SSL
Unlike blocking IO, the JVM does not provide standard SSLSocketChannel and SSLServerSocketChannel classes that extend the base socket channel classes. Instead the SSL exchanges must be manually orchestrated using a <a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLEngine.html">SSLEngine</a>. 
This project provides implementations for <a href="http://baswerc.github.io/niossl/javadoc/org/baswell/niossl/SSLSocketChannel.html">SSLSocketChannel</a> and <a href="http://baswerc.github.io/niossl/javadoc/org/baswell/niossl/SSLServerSocketChannel.html">SSLServerSocketChannel</a> that can be used like
<a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLSocket.html">SSLSocket</a> and <a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLServerSocket.html">SSLServerSocket</a>.

## Getting Started

### Direct Download
You can download <a href="https://github.com/baswerc/niossl/releases/download/v0.1/niossl-0.1.jar">niossl-0.1.jar</a> directly and place in your project.

### Using Maven
Add the following dependency into your Maven project:

````xml
<dependency>
    <groupId>org.baswell</groupId>
    <artifactId>niossl</artifactId>
    <version>0.1</version>
</dependency>
````

### Copy Source
This project is only a couple of source files with no external dependencies. You can just <a href="https://github.com/baswerc/niossl/archive/v0.1.zip">copy these source files</a> directly in our project.

## Using SSLSocketChannel

```Java
SSLContext sslContext = SSLContext.getInstance("TLS");
SSLEngine sslEngine = sslContext.createSSLEngine("localhost", 443);
sslEngine.setUseClientMode(true); 
SSLSocketChannel sslSocketChannel = new SSLSocketChannel(socketChannel, sslEngine, sslThreadPool, getLogger());
// At this point you can use sslSocketChannel like you would a SocketChannel
```

## Using SSLServerSocketChannel

```Java
ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
serverSocketChannel.socket().bind(new InetSocketAddress(443));

SSLContext sslContext = SSLContext.getInstance("TLS");
ThreadPoolExecutor sslThreadPool = new ThreadPoolExecutor(250, 2000, 25, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>());

NioSslLogger logger = ... // This can be null to disable logging

SSLServerSocketChannel sslServerSocketChannel = new SSLServerSocketChannel(serverSocketChannel, serverContext, sslThreadPool, logger);
acceptLoop.start(sslServerSocketChannel);
// At this point you can use sslServerSocketChannel like you would a ServerSocketChannel
```

# Additional Documentation

* <a href="http://baswerc.github.io/niossl/javadoc/">Javadoc</a>

# Developed By

Corey Baswell - <a href="mailto:corey.baswell@gmail.com">corey.baswell@gmail.com</a>

# License
````
Copyright 2015 Corey Baswell

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
````