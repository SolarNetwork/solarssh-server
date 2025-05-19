/* ==================================================================
 * AsyncTextOutputStream.java - 23/06/2017 3:28:36 PM
 * 
 * Copyright 2017 SolarNetwork.net Dev Team
 * 
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 
 * 02111-1307 USA
 * ==================================================================
 */

package net.solarnetwork.solarssh.web;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;

import jakarta.websocket.CloseReason;
import jakarta.websocket.RemoteEndpoint.Async;
import jakarta.websocket.Session;

/**
 * Write websocket text messages as an OutputStream.
 * 
 * @author matt
 * @version 1.0
 */
public class AsyncTextOutputStream extends OutputStream {

  private final Session session;
  private final Async remote;
  private final Charset charset = Charset.forName("UTF-8");

  /**
   * Wraps a websocket {@code Session} as a text-oriented {@link OutputStream} using the socket's
   * {@code RemoteEndpoint.Async} API.
   * 
   * @param session
   *        the session to wrap
   * @throws IOException
   *         if a communication error occurs
   */
  public AsyncTextOutputStream(Session session) throws IOException {
    super();
    this.session = session;
    this.remote = session.getAsyncRemote();
    remote.setBatchingAllowed(true);
  }

  @Override
  public void write(int b) throws IOException {
    remote.sendText(new String(new byte[] { (byte) (b & 0xFF) }, charset));

  }

  @Override
  public void write(byte[] b) throws IOException {
    remote.sendText(new String(b, charset));
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    remote.sendText(new String(b, off, len, charset));
  }

  @Override
  public void flush() throws IOException {
    remote.flushBatch();
  }

  /**
   * Close the output stream, and close the websocket session.
   */
  @Override
  public void close() throws IOException {
    session.close(new CloseReason(CloseReason.CloseCodes.NORMAL_CLOSURE, "Connection closed"));
  }

}
