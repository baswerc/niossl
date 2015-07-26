/*
 * Copyright 2015 Corey Baswell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.baswell.niossl;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;

class SSLEngineBuffer
{
  private final SocketChannel socketChannel;

  private final SSLEngine sslEngine;

  private final ExecutorService executorService;

  private final ByteBuffer networkInboundBuffer;

  private final ByteBuffer networkOutboundBuffer;

  private final int minimumApplicationBufferSize;

  private final ByteBuffer unwrapBuffer;

  private final ByteBuffer wrapBuffer;

  private final NioSslLogger log;

  private final boolean logDebug;

  public SSLEngineBuffer(SocketChannel socketChannel, SSLEngine sslEngine, ExecutorService executorService, NioSslLogger log)
  {
    this.socketChannel = socketChannel;
    this.sslEngine = sslEngine;
    this.executorService = executorService;
    this.log = log;

    logDebug = log != null && log.logDebugs();

    SSLSession session = sslEngine.getSession();
    int networkBufferSize = session.getPacketBufferSize();

    networkInboundBuffer = ByteBuffer.allocate(networkBufferSize);

    networkOutboundBuffer = ByteBuffer.allocate(networkBufferSize);
    networkOutboundBuffer.flip();


    minimumApplicationBufferSize = session.getApplicationBufferSize();
    unwrapBuffer = ByteBuffer.allocate(minimumApplicationBufferSize);
    wrapBuffer = ByteBuffer.allocate(minimumApplicationBufferSize);
    wrapBuffer.flip();
  }

  int unwrap(ByteBuffer applicationInputBuffer) throws IOException
  {
    if (applicationInputBuffer.capacity() < minimumApplicationBufferSize)
    {
      throw new IllegalArgumentException("Application buffer size must be at least: " + minimumApplicationBufferSize);
    }

    if (unwrapBuffer.position() != 0)
    {
      unwrapBuffer.flip();
      while (unwrapBuffer.hasRemaining() && applicationInputBuffer.hasRemaining())
      {
        applicationInputBuffer.put(unwrapBuffer.get());
      }
      unwrapBuffer.compact();
    }

    int totalUnwrapped = 0;
    int unwrapped, wrapped;

    do
    {
      totalUnwrapped += unwrapped = doUnwrap(applicationInputBuffer);
      wrapped = doWrap(wrapBuffer);
    }
    while (unwrapped > 0 || wrapped > 0 && (networkOutboundBuffer.hasRemaining() && networkInboundBuffer.hasRemaining()));

    return totalUnwrapped;
  }

  int wrap(ByteBuffer applicationOutboundBuffer) throws IOException
  {
    int wrapped = doWrap(applicationOutboundBuffer);
    doUnwrap(unwrapBuffer);
    return wrapped;
  }

  int flushNetworkOutbound() throws IOException
  {
    return send(socketChannel, networkOutboundBuffer);
  }

  int send(SocketChannel channel, ByteBuffer buffer) throws IOException
  {
    int totalWritten = 0;
    while (buffer.hasRemaining())
    {
      int written = channel.write(buffer);

      if (written == 0)
      {
        break;
      }
      else if (written < 0)
      {
        return (totalWritten == 0) ? written : totalWritten;
      }
      totalWritten += written;
    }
    if (logDebug) log.debug("sent: " + totalWritten + " out to socket");
    return totalWritten;
  }

  void close()
  {
    try
    {
      sslEngine.closeInbound();
    }
    catch (Exception e)
    {}

    try
    {
      sslEngine.closeOutbound();
    }
    catch (Exception e)
    {}
  }

  private int doUnwrap(ByteBuffer applicationInputBuffer) throws IOException
  {
    if (logDebug) log.debug("unwrap:");

    int totalReadFromChannel = 0;

    // Keep looping until peer has no more data ready or the applicationInboundBuffer is full
    UNWRAP: do
    {
      // 1. Pull data from peer into networkInboundBuffer

      int readFromChannel = 0;
      while (networkInboundBuffer.hasRemaining())
      {
        int read = socketChannel.read(networkInboundBuffer);
        if (logDebug) log.debug("unwrap: socket read " + read + "(" + readFromChannel + ", " + totalReadFromChannel + ")");
        if (read <= 0)
        {
          if ((read < 0) && (readFromChannel == 0) && (totalReadFromChannel == 0))
          {
            // No work done and we've reached the end of the channel from peer
            if (logDebug) log.debug("unwrap: exit: end of channel");
            return read;
          }
          break;
        }
        else
        {
          readFromChannel += read;
        }
      }


      networkInboundBuffer.flip();
      if (!networkInboundBuffer.hasRemaining())
      {
        networkInboundBuffer.compact();
        //wrap(applicationOutputBuffer, applicationInputBuffer, false);
        return totalReadFromChannel;
      }

      totalReadFromChannel += readFromChannel;

      try
      {
        SSLEngineResult result = sslEngine.unwrap(networkInboundBuffer, applicationInputBuffer);
        if (logDebug) log.debug("unwrap: result: " + result);

        switch (result.getStatus())
        {
          case OK:
            SSLEngineResult.HandshakeStatus handshakeStatus = result.getHandshakeStatus();
            switch (handshakeStatus)
            {
              case NEED_UNWRAP:
                break;

              case NEED_WRAP:
                break UNWRAP;

              case NEED_TASK:
                runHandshakeTasks();
                break;

              case NOT_HANDSHAKING:
              default:
                break;
            }
            break;

          case BUFFER_OVERFLOW:
            if (logDebug) log.debug("unwrap: buffer overflow");
            break UNWRAP;

          case CLOSED:
            if (logDebug) log.debug("unwrap: exit: ssl closed");
            return totalReadFromChannel == 0 ? -1 : totalReadFromChannel;

          case BUFFER_UNDERFLOW:
            if (logDebug) log.debug("unwrap: buffer underflow");
            break;
        }
      }
      finally
      {
        networkInboundBuffer.compact();
      }
    }
    while (applicationInputBuffer.hasRemaining());

    return totalReadFromChannel;
  }

  private int doWrap(ByteBuffer applicationOutboundBuffer) throws IOException
  {
    if (logDebug) log.debug("wrap:");
    int totalWritten = 0;

    // 1. Send any data already wrapped out channel

    if (networkOutboundBuffer.hasRemaining())
    {
      totalWritten = send(socketChannel, networkOutboundBuffer);
      if (totalWritten < 0)
      {
        return totalWritten;
      }
    }

    // 2. Any data in application buffer ? Wrap that and send it to peer.

    WRAP: while (true)
    {
      networkOutboundBuffer.compact();
      SSLEngineResult result = sslEngine.wrap(applicationOutboundBuffer, networkOutboundBuffer);
      if (logDebug) log.debug("wrap: result: " + result);

      networkOutboundBuffer.flip();
      if (networkOutboundBuffer.hasRemaining())
      {
        int written = send(socketChannel, networkOutboundBuffer);
        if (written < 0)
        {
          return totalWritten == 0 ? written : totalWritten;
        }
        else
        {
          totalWritten += written;
        }
      }

      switch (result.getStatus())
      {
        case OK:
          switch (result.getHandshakeStatus())
          {
            case NEED_WRAP:
              break;

            case NEED_UNWRAP:
              break WRAP;

            case NEED_TASK:
              runHandshakeTasks();
              if (logDebug) log.debug("wrap: exit: need tasks");
              break;

            case NOT_HANDSHAKING:
              if (applicationOutboundBuffer.hasRemaining())
              {
                break;
              }
              else
              {
                break WRAP;
              }
          }
          break;

        case BUFFER_OVERFLOW:
          if (logDebug) log.debug("wrap: exit: buffer overflow");
          break WRAP;

        case CLOSED:
          if (logDebug) log.debug("wrap: exit: closed");
          break WRAP;

        case BUFFER_UNDERFLOW:
          if (logDebug) log.debug("wrap: exit: buffer underflow");
          break WRAP;
      }
    }

    if (logDebug) log.debug("wrap: return: " + totalWritten);
    return totalWritten;
  }

  private void runHandshakeTasks ()
  {
    while (true)
    {
      final Runnable runnable = sslEngine.getDelegatedTask();
      if (runnable == null)
      {
        break;
      }
      else
      {
        executorService.execute(runnable);
      }
    }
  }
}
