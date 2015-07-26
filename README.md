# NIO SSL
Unlike blocking IO, the JVM does not provide standard SSLSocketChannel and SSLServerSocketChannel classes that extend the base socket channel classes. Instead the SSL exchanges must be manually orchestrated using a <a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLEngine.html">SSLEngine</a>. 
This project provides implementations for <a href="http://baswerc.github.io/niossl/javadoc/org/baswell/niossl/SSLSocketChannel.html">SSLSocketChannel</a> and <a href="http://baswerc.github.io/niossl/javadoc/org/baswell/niossl/SSLServerSocketChannel.html">SSLServerSocketChannel</a> that can be used like
<a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLSocket.html">SSLSocket</a> and <a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLServerSocket.html">SSLServerSocket</a>.

## Getting Started

### Direct Download
You can download <a href="https://github.com/baswerc/niossl/releases/download/v0.2/niossl-0.2.jar">niossl-0.2.jar</a> directly and place in your project.

### Using Maven
Add the following dependency into your Maven project:

````xml
<dependency>
    <groupId>org.baswell</groupId>
    <artifactId>niossl</artifactId>
    <version>0.2</version>
</dependency>
````

### Copy Source
This project is only a couple of source files with no external dependencies. You can just <a href="https://github.com/baswerc/niossl/archive/v0.2.zip">copy these source files</a> directly in your project.


## Using SSLSocketChannel
<a href="http://baswerc.github.io/niossl/javadoc/org/baswell/niossl/SSLSocketChannel.html">SSLSocketChannel</a> is constructed from a normal ```SocketChannel``` and the necessary SSL related information. Once the
```SSLSocketChannel``` is created its ```read``` and ```write``` methods can be used to receive and send data over a SSL network connection.

```Java
SocketChannel socketChannel = SocketChannel.open(new InetSocketAddress("test.com", 443););
socketChannel.configureBlocking(false);

SSLContext sslContext = SSLContext.getInstance("TLS");
SSLEngine sslEngine = sslContext.createSSLEngine();
sslEngine.setUseClientMode(true); 

ThreadPoolExecutor sslThreadPool = new ThreadPoolExecutor(250, 2000, 25, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>()); // Thread pool for executing long-running SSL tasks
NioSslLogger logger = null; // null disables logging

SSLSocketChannel sslSocketChannel = new SSLSocketChannel(socketChannel, sslEngine, sslThreadPool, getLogger());

// At this point you can use sslSocketChannel like you would a normal SocketChannel
```

### Registering With Selectors
```SSLSocketChannel``` cannot be registered directly with a <a href="http://docs.oracle.com/javase/7/docs/api/java/nio/channels/Selector.html">Selector</a>. Instead you must use the real ```SocketChannel``` instance that the ```SSLSocketChannel``` was constructed with.

```Java
SelectionKey selectionKey = sslSocketChannel.getWrappedSocketChannel().register(selector, SelectionKey.OP_READ);
selectionKey.attach(sslSocketChannel);
```

### Application Buffer Size
The application buffers you pass in on calls to ```SSLSocketChannel.read``` and ```SSLSocketChannel.write``` must be of a minimum size to ensure that the ```SSLEngine``` has enough buffer to perform the SSL exchanges. An ```IllegalArgumentException``` will thrown 
from either of these read or write methods if the application buffer size passed in is smaller than the current size of the <a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLSession.html#getApplicationBufferSize()">largest expected data packet sent or received</a>.

```Java
SSLContext sslContext = SSLContext.getInstance("TLS");
SSLEngine sslEngine = sslContext.createSSLEngine();
sslEngine.setUseClientMode(true); 

int minAppBufferSize = sslEngine.getSession().getApplicationBufferSize(); // Your buffers must be at least this big.
```

## Using SSLServerSocketChannel
<a href="http://baswerc.github.io/niossl/javadoc/org/baswell/niossl/SSLServerSocketChannel.html">SSLServerSocketChannel</a> is used like a normal ```ServerSocketChannel```. Once the ```SSLServerSocketChannel``` is constructed with the required
SSL parameters, blocking calls to ```accept()``` or  ```acceptOverSSL()``` can be made to process incoming requests. The ```SocketChannel``` objects returned from ```accept()``` are instances of <a href="http://baswerc.github.io/niossl/javadoc/org/baswell/niossl/SSLSocketChannel.html">SSLSocketChannel</a>.

```Java
ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
serverSocketChannel.socket().bind(new InetSocketAddress(443));

SSLContext sslContext = SSLContext.getInstance("TLS");
ThreadPoolExecutor sslThreadPool = new ThreadPoolExecutor(250, 2000, 25, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>()); // Thread pool for executing long-running SSL tasks

NioSslLogger logger = null; // null disables logging

SSLServerSocketChannel sslServerSocketChannel = new SSLServerSocketChannel(serverSocketChannel, serverContext, sslThreadPool, logger);

while (true)
{
  SSLSocketChannel sslSocketChannel = sslServerSocketChannel.acceptOverSSL(); // blocks until a SocketChannel is ready
  dispatch(sslSocketChannel);
}
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