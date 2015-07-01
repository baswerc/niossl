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
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;

/**
 * A wrapper around a real {@link SocketChannel} that adds SSL support.
 */
public class SSLSocketChannel extends SocketChannel
{
  private final SocketChannel socketChannel;

  private final SSLEngine sslEngine;

  private final ExecutorService executorService;

  private final NioSslLogger log;

  private final boolean logDebug;

  private final ByteBuffer networkInboundBuffer;

  private final ByteBuffer applicationInboundBuffer;

  private final ByteBuffer networkOutboundBuffer;

  private final ByteBuffer applicationOutboundBuffer;

  /**
   *
   * @param socketChannel The real SocketChannel.
   * @param sslEngine The SSL engine to use for traffic back and forth on the given SocketChannel.
   * @param executorService Used to execute long running, blocking SSL operations such as certificate validation with a CA (<a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLEngineResult.HandshakeStatus.html#NEED_TASK">NEED_TASK</a>)
   * @param log The logger for debug and error messages. A null logger will result in no log operations.
   */
  public SSLSocketChannel(SocketChannel socketChannel, SSLEngine sslEngine, ExecutorService executorService, NioSslLogger log)
  {
    super(socketChannel.provider());
    this.socketChannel = socketChannel;
    this.sslEngine = sslEngine;
    this.executorService = executorService;
    this.log = log;

    logDebug = log != null && log.logDebugs();

    SSLSession session = sslEngine.getSession();
    int applicationBufferSize = session.getApplicationBufferSize();
    int networkBufferSize = session.getPacketBufferSize();

    networkInboundBuffer = ByteBuffer.allocate(networkBufferSize);

    applicationInboundBuffer = ByteBuffer.allocate(applicationBufferSize);
    applicationInboundBuffer.flip();

    networkOutboundBuffer = ByteBuffer.allocate(networkBufferSize);
    networkOutboundBuffer.flip();

    applicationOutboundBuffer = ByteBuffer.allocate(applicationBufferSize);
  }

   public SocketChannel getRealSocketChannel()
  {
    return socketChannel;
  }

  @Override
  synchronized public int read(ByteBuffer applicationBuffer) throws IOException
  {
    int intialPosition = applicationBuffer.position();

    if (applicationInboundBuffer.hasRemaining())
    {
      applicationBuffer.put(applicationInboundBuffer);
    }

    int readFromChannel = unwrap(true);

    int amountInAppBuffer = applicationBuffer.remaining();
    int amountInInboundBuffer = applicationInboundBuffer.remaining();
    if (amountInAppBuffer > 0 && amountInInboundBuffer > 0)
    {
      if (amountInAppBuffer >= amountInInboundBuffer)
      {
        applicationBuffer.put(applicationInboundBuffer);
      }
      else
      {
        while (applicationBuffer.hasRemaining())
        {
          applicationBuffer.put(applicationInboundBuffer.get());
        }
      }
    }

    int totalRead = applicationBuffer.position() - intialPosition;
    if (totalRead == 0 && readFromChannel < 0)
    {
      totalRead = readFromChannel;
    }
    else if (applicationOutboundBuffer.hasRemaining())
    {
      wrap(true);
    }


    if (logDebug) log.debug("read: total read: " + totalRead);
    return totalRead;
  }

  @Override
  synchronized public int write(ByteBuffer applicationBuffer) throws IOException
  {
    // 1. Fill applicationOutboundBuffer

    int initialAppBufferPosition = applicationBuffer.position();
    int intialAppOutboundBufferPosition = applicationOutboundBuffer.position();
    int initialNeworkOutboundBufferPosition = networkOutboundBuffer.position();

    applicationOutboundBuffer.put(applicationBuffer);
    int writtenToBuffer = applicationBuffer.position() - initialAppBufferPosition;

    // 2. Wrap data and attempt to send to network peer

    int writtenToChannel = wrap(true);
    if (writtenToChannel <= 0)
    {
      /*
       * If no data was written to outbound channel, it's possible the network buffer is full. The caller of this method
       * needs to know that no data was actually written in case they want to register for a write ready event.
       */
      applicationBuffer.position(initialAppBufferPosition);
      applicationOutboundBuffer.position(intialAppOutboundBufferPosition);
      networkOutboundBuffer.position(initialNeworkOutboundBufferPosition);

      writtenToBuffer = writtenToChannel;
    }

    if (logDebug) log.debug("write: total written: " + writtenToBuffer);
    return writtenToBuffer;
  }

  /*
   * Buffer pre and post conditions:
   *
   * networkInboundBuffer pre: write, post: write
   * applicationInboundBuffer pre: read, post: read
   *
   */
  synchronized int unwrap(boolean wrapIfNeeded) throws IOException
  {
    if (logDebug) log.debug("unwrap:");

    int totalReadFromSocket = 0;

    applicationInboundBuffer.compact();
    try
    {
      // Keep looping until peer has no more data ready or the applicationInboundBuffer is full
      while (true)
      {
        // 1. Pull data from peer into networkInboundBuffer

        int readFromSocket = 0;
        while (networkInboundBuffer.hasRemaining())
        {
          int read = socketChannel.read(networkInboundBuffer);
          if (logDebug) log.debug("unwrap: socket read " + read + "(" + readFromSocket + ", " + totalReadFromSocket + ")");
          if (read <= 0)
          {
            if ((read < 0) && (readFromSocket == 0) && (totalReadFromSocket == 0))
            {
              // No work done and we've reached the end of the channel from peer
              if (logDebug) log.debug("unwrap: exit: end of channel");
              return read;
            }
            break;
          }
          else
          {
            readFromSocket += read;
          }
        }

        networkInboundBuffer.flip();
        if (readFromSocket == 0 && !networkInboundBuffer.hasRemaining())
        {
          networkInboundBuffer.compact();
          return totalReadFromSocket;
        }

        totalReadFromSocket += readFromSocket;

        try
        {
          SSLEngineResult result = sslEngine.unwrap(networkInboundBuffer, applicationInboundBuffer);
          if (logDebug) log.debug("unwrap: result: " + result);

          switch (result.getStatus())
          {
            case OK:
              HandshakeStatus handshakeStatus = result.getHandshakeStatus();
              switch (handshakeStatus)
              {
                case NEED_UNWRAP:
                  break;

                case NEED_WRAP:
                  if (wrap(true) == 0)
                  {
                    if (logDebug) log.debug("unwrap: exit: wrap needed with no data written");
                    return totalReadFromSocket;
                  }
                  break;

                case NEED_TASK:
                  dispatchLongRunningTasks();
                  if (logDebug) log.debug("unwrap: exit: need tasks");
                  break;

                case NOT_HANDSHAKING:
                default:
                  break;
              }
              break;

            case BUFFER_OVERFLOW:
              // Assume that we've already made progressed and put data in applicationInboundBuffer
              return totalReadFromSocket;

            case CLOSED:
              if (logDebug) log.debug("unwrap: exit: ssl closed");
              return totalReadFromSocket == 0 ? -1 : totalReadFromSocket;

            case BUFFER_UNDERFLOW:
              // Assume that we've already made progressed and put data in applicationInboundBuffer
              return totalReadFromSocket;
          }
        }
        finally
        {
          networkInboundBuffer.compact();
        }
      }
    }
    finally
    {
      applicationInboundBuffer.flip();
    }
  }

  /*
   * Buffer pre and post conditions:
   *
   * networkOutboundBuffer pre: read, post read:
   * applicationOutboundBuffer pre: write, post: write
   *
   */
  synchronized int wrap(boolean unwrapIfNecessary) throws IOException
  {
    if (logDebug) log.debug("wrap");
    int totalWritten = 0;

    sslEngine.wrap(applicationOutboundBuffer, networkOutboundBuffer);

    // 1. Any data already wrapped ? Go ahead and send that.
    while (networkOutboundBuffer.hasRemaining())
    {
      int written = socketChannel.write(networkOutboundBuffer);
      totalWritten += written;
      if (logDebug) log.debug("wrap: pre socket write: " + written + " (" + totalWritten + ")");

      if (written <= 0)
      {
        return (totalWritten == 0 && written < 0) ? written : totalWritten;
      }
    }

    // 2. Any data in application buffer ? Wrap that and send it to peer.

    applicationOutboundBuffer.flip();
    networkOutboundBuffer.compact();
    try
    {
      WRAP: while (applicationOutboundBuffer.hasRemaining() || networkOutboundBuffer.hasRemaining())
      {
        SSLEngineResult result = sslEngine.wrap(applicationOutboundBuffer, networkOutboundBuffer);
        if (logDebug) log.debug("wrap: result: " + result);
        networkOutboundBuffer.flip();
        try
        {
          // Was any encrypted application data produced ? If so go ahead and try to send to peer.
          int written = 0;
          while (networkOutboundBuffer.hasRemaining())
          {
            int nextWritten = socketChannel.write(networkOutboundBuffer);
            if (logDebug) log.debug("wrap: post socket write: " + nextWritten + " (" + written + ")");

            if (nextWritten == 0)
            {
              break;
            }
            else if (nextWritten < 0)
            {
              totalWritten += written;
              return (totalWritten == 0) ? nextWritten : totalWritten;
            }
            written += nextWritten;
          }

          if (logDebug) log.debug("wrap: post socket write: " + written + " (" + totalWritten + ")");

          totalWritten += written;

          switch (result.getStatus())
          {
            case OK:
              HandshakeStatus handshakeStatus = result.getHandshakeStatus();
              switch (handshakeStatus)
              {
                case NEED_WRAP:
                  // Not enough data in applicationOutboundBuffer.
                  if (written == 0)
                  {
                    if (logDebug) log.debug("wrap: exit: need wrap & no data written");
                    break WRAP;
                  }
                  break;

                case NEED_UNWRAP:
                  if (unwrap(false) == 0)
                  {
                    break WRAP;
                  }
                  break;

                case NEED_TASK:
                  dispatchLongRunningTasks();
                  if (logDebug) log.debug("wrap: exit: need tasks");
                  break;

                case NOT_HANDSHAKING:
                  if (written <= 0)
                  {
                    if (logDebug) log.debug("wrap: exit: no data written");
                    break WRAP;
                  }
              }
              break;

            case BUFFER_OVERFLOW:
              throw new IOException("Buffer overflow.");

            case CLOSED:
              if (logDebug) log.debug("wrap: exit: closed");
              break WRAP;

            case BUFFER_UNDERFLOW:
              // Need more data in applicationOutboundBuffer
              if (logDebug) log.debug("wrap: exit: buffer underflow");
              break WRAP;
          }
        }
        finally
        {
          networkOutboundBuffer.compact();
        }
      }
    }
    finally
    {
      applicationOutboundBuffer.compact();
      networkOutboundBuffer.flip();
    }

    if (logDebug) log.debug("wrap: return: " + totalWritten);

    return totalWritten;
  }


  @Override
  public long read(ByteBuffer[] byteBuffers, int offset, int length) throws IOException
  {
    long totalRead = 0;
    for (int i = offset; i < length; i++)
    {
      ByteBuffer byteBuffer = byteBuffers[i];
      if (byteBuffer.hasRemaining())
      {
        int read = read(byteBuffer);
        if (read > 0)
        {
          totalRead += read;
          if (byteBuffer.hasRemaining())
          {
            break;
          }
        }
        else
        {
          if ((read < 0) && (totalRead == 0))
          {
            totalRead = -1;
          }
          break;
        }
      }
    }
    return totalRead;
  }

  @Override
  public long write(ByteBuffer[] byteBuffers, int offset, int length) throws IOException
  {
    long totalWritten = 0;
    for (int i = offset; i < length; i++)
    {
      ByteBuffer byteBuffer = byteBuffers[i];
      if (byteBuffer.hasRemaining())
      {
        int written = write(byteBuffer);
        if (written > 0)
        {
          totalWritten += written;
          if (byteBuffer.hasRemaining())
          {
            break;
          }
        }
        else
        {
          if ((written < 0) && (totalWritten == 0))
          {
            totalWritten = -1;
          }
          break;
        }
      }
    }
    return totalWritten;
  }

  /*
  @Override
  public SocketChannel bind(SocketAddress local) throws IOException
  {
    socketChannel.bind(local);
    return this;
  }

  @Override
  public SocketAddress getLocalAddress() throws IOException
  {
    return socketChannel.getLocalAddress();
  }

  @Override
  public <T> SocketChannel setOption(SocketOption<T> name, T value) throws IOException
  {
    return socketChannel.setOption(name, value);
  }

  @Override
  public <T> T getOption(SocketOption<T> name) throws IOException
  {
    return socketChannel.getOption(name);
  }

  @Override
  public Set<SocketOption<?>> supportedOptions()
  {
    return socketChannel.supportedOptions();
  }

  @Override
  public SocketChannel shutdownInput() throws IOException
  {
    return socketChannel.shutdownInput();
  }

  @Override
  public SocketChannel shutdownOutput() throws IOException
  {
    return socketChannel.shutdownOutput();
  }
  */

  @Override
  public Socket socket ()
  {
    return socketChannel.socket();
  }

  @Override
  public boolean isConnected ()
  {
    return socketChannel.isConnected();
  }

  @Override
  public boolean isConnectionPending ()
  {
    return socketChannel.isConnectionPending();
  }

  @Override
  public boolean connect (SocketAddress socketAddress)throws IOException
  {
    return socketChannel.connect(socketAddress);
  }

  @Override
  public boolean finishConnect ()throws IOException
  {
    return socketChannel.finishConnect();
  }

  /*
  @Override
  public SocketAddress getRemoteAddress() throws IOException
  {
    return socketChannel.getRemoteAddress();
  }
  */

  @Override
  protected void implCloseSelectableChannel ()throws IOException
  {
    if (networkOutboundBuffer.hasRemaining())
    {
      try
      {
        socketChannel.write(networkOutboundBuffer);
      }
      catch (Exception e)
      {}
    }

    socketChannel.close();
    sslEngine.closeInbound();
    sslEngine.closeOutbound();
  }

  @Override
  protected void implConfigureBlocking ( boolean b)throws IOException
  {
    socketChannel.configureBlocking(b);
  }

  void dispatchLongRunningTasks()
  {
    Runnable runnable;
    while ((runnable = sslEngine.getDelegatedTask()) != null)
    {
      executorService.execute(runnable);
    }
  }
}