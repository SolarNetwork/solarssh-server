/* ==================================================================
 * DynamicDirectTcpipFactory.java - 11/08/2020 1:48:59 PM
 * 
 * Copyright 2020 SolarNetwork.net Dev Team
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

package net.solarnetwork.solarssh.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.function.IntUnaryOperator;
import java.util.logging.Level;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferException;
import org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser;
import org.apache.sshd.common.util.logging.SimplifiedLog;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.forward.TcpForwardingFilter.Type;
import org.apache.sshd.server.forward.TcpipServerChannel;
import org.apache.sshd.server.forward.TcpipServerChannel.TcpipFactory;

import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * Factory for dynamically-allocated direct-tcpip ports.
 * 
 * @author matt
 * @version 1.2
 */
public class DynamicDirectTcpipFactory extends TcpipFactory {

  private final String fixedDestinationHost;
  private final SshSessionDao sessionDao;

  /**
   * Constructor.
   * 
   * @param sessionDao
   *        the session DAO
   */
  public DynamicDirectTcpipFactory(SshSessionDao sessionDao) {
    this(sessionDao, "127.0.0.1");
  }

  /**
   * Constructor.
   * 
   * @param sessionDao
   *        the session DAO
   * @param fixedDestinationHost
   *        the fixed destination host
   */
  public DynamicDirectTcpipFactory(SshSessionDao sessionDao, String fixedDestinationHost) {
    super(Type.Direct);
    this.sessionDao = sessionDao;
    this.fixedDestinationHost = fixedDestinationHost;
  }

  @Override
  public Channel createChannel(Session session) throws IOException {
    // TODO get port from session (or allocate dynamic port now?)
    SshSession sshSession = sessionDao.findOne(session);
    if (sshSession == null) {
      throw new IllegalArgumentException("No SshSession available.");
    }
    int port = sshSession.getReverseSshPort();
    return new ReservedTcpIpServerChannel(port, getType(),
        ThreadUtils.noClose(getExecutorService()));
  }

  private final class ReservedTcpIpServerChannel extends TcpipServerChannel {

    private final int fixedDestinationPort;

    public ReservedTcpIpServerChannel(int port, Type type, CloseableExecutorService executor) {
      super(type, executor);
      this.fixedDestinationPort = port;
    }

    @Override
    protected OpenFuture doInit(Buffer buffer) {
      // read the provided destination host/port values to move the rpos forward
      String hostToConnect = buffer.getString();
      int portToConnect = buffer.getInt();

      log.debug("Client requested dest {}:{} will be forced to {}:{}", hostToConnect, portToConnect,
          fixedDestinationHost, fixedDestinationPort);

      // now call super() but passed reserved buffer that will returned fixed host/port values
      ReservedHostBuffer maskedBuffer = new ReservedHostBuffer(buffer, fixedDestinationPort);

      return super.doInit(maskedBuffer);
    }

  }

  private final class ReservedHostBuffer extends Buffer {

    private final Buffer delegate;
    private final int fixedDestinationPort;
    private boolean destHostReturned;
    private boolean destPortReturned;

    private ReservedHostBuffer(Buffer delegate, int fixedDestinationPort) {
      super();
      this.delegate = delegate;
      this.fixedDestinationPort = fixedDestinationPort;
      this.destHostReturned = false;
      this.destPortReturned = false;
    }

    @Override
    public String getString() {
      if (!destHostReturned) {
        destHostReturned = true;
        return fixedDestinationHost;
      }
      return delegate.getString();
    }

    @Override
    public String getString(Charset charset) {
      return delegate.getString(charset);
    }

    @Override
    public int getInt() {
      if (!destPortReturned) {
        destPortReturned = true;
        return fixedDestinationPort;
      }
      return delegate.getInt();
    }

    @Override
    protected void copyRawBytes(int offset, byte[] buf, int pos, int len) {
      if ((offset < 0) || (pos < 0) || (len < 0)) {
        throw new IndexOutOfBoundsException(
            "Invalid offset(" + offset + ")/position(" + pos + ")/length(" + len + ") required");
      }
      byte[] data = delegate.array();
      System.arraycopy(data, delegate.rpos() + offset, buf, pos, len);
    }

    @Override
    protected int size() {
      return delegate.array().length;
    }

    @Override
    public int available() {
      return delegate.available();
    }

    @Override
    public byte[] getBytesConsumed(int from) {
      return delegate.getBytesConsumed(from);
    }

    @Override
    public void getRawBytes(byte[] data, int offset, int len) {
      delegate.getRawBytes(data, offset, len);
    }

    @Override
    public void getRawBytes(byte[] buf) {
      delegate.getRawBytes(buf);
    }

    @Override
    public int hashCode() {
      return delegate.hashCode();
    }

    @Override
    public int rpos() {
      return delegate.rpos();
    }

    @Override
    public void rpos(int rpos) {
      delegate.rpos(rpos);
    }

    @Override
    public int wpos() {
      return delegate.wpos();
    }

    @Override
    public void wpos(int wpos) {
      delegate.wpos(wpos);
    }

    @Override
    public boolean equals(Object obj) {
      return delegate.equals(obj);
    }

    @Override
    public int capacity() {
      return delegate.capacity();
    }

    @Override
    public byte[] array() {
      return delegate.array();
    }

    @Override
    public byte[] getBytesConsumed() {
      return delegate.getBytesConsumed();
    }

    @Override
    public byte rawByte(int pos) {
      return delegate.rawByte(pos);
    }

    @Override
    public long rawUInt(int pos) {
      return delegate.rawUInt(pos);
    }

    @Override
    public void compact() {
      delegate.compact();
    }

    @Override
    public byte[] getCompactData() {
      return delegate.getCompactData();
    }

    @Override
    public Buffer clear() {
      return delegate.clear();
    }

    @Override
    public Buffer clear(boolean wipeData) {
      return delegate.clear(wipeData);
    }

    @Override
    public boolean isValidMessageStructure(Class<?>... fieldTypes) {
      return delegate.isValidMessageStructure(fieldTypes);
    }

    @Override
    public boolean isValidMessageStructure(Collection<Class<?>> fieldTypes) {
      return delegate.isValidMessageStructure(fieldTypes);
    }

    @Override
    public String toHex() {
      return delegate.toHex();
    }

    @Override
    public void dumpHex(SimplifiedLog logger, String prefix, PropertyResolver resolver) {
      delegate.dumpHex(logger, prefix, resolver);
    }

    @Override
    public void dumpHex(SimplifiedLog logger, Level level, String prefix,
        PropertyResolver resolver) {
      delegate.dumpHex(logger, level, prefix, resolver);
    }

    @Override
    public int getUByte() {
      return delegate.getUByte();
    }

    @Override
    public byte getByte() {
      return delegate.getByte();
    }

    @Override
    public short getShort() {
      return delegate.getShort();
    }

    @Override
    public long getUInt() {
      return delegate.getUInt();
    }

    @Override
    public long getLong() {
      return delegate.getLong();
    }

    @Override
    public boolean getBoolean() {
      return delegate.getBoolean();
    }

    @Override
    public List<String> getNameList() {
      return delegate.getNameList();
    }

    @Override
    public List<String> getNameList(Charset charset) {
      return delegate.getNameList(charset);
    }

    @Override
    public List<String> getNameList(char separator) {
      return delegate.getNameList(separator);
    }

    @Override
    public List<String> getNameList(Charset charset, char separator) {
      return delegate.getNameList(charset, separator);
    }

    @Override
    public Collection<String> getAvailableStrings() {
      return delegate.getAvailableStrings();
    }

    @Override
    public Collection<String> getAvailableStrings(Charset charset) {
      return delegate.getAvailableStrings(charset);
    }

    @Override
    public Collection<String> getStringList(boolean usePrependedLength, Charset charset) {
      return delegate.getStringList(usePrependedLength, charset);
    }

    @Override
    public Collection<String> getStringList(boolean usePrependedLength) {
      return delegate.getStringList(usePrependedLength);
    }

    @Override
    public List<String> getStringList(int count) {
      return delegate.getStringList(count);
    }

    @Override
    public List<String> getStringList(int count, Charset charset) {
      return delegate.getStringList(count, charset);
    }

    @Override
    public BigInteger getMPInt() {
      return delegate.getMPInt();
    }

    @Override
    public byte[] getMPIntAsBytes() {
      return delegate.getMPIntAsBytes();
    }

    @Override
    public byte[] getBytes() {
      return delegate.getBytes();
    }

    @Override
    public PublicKey getPublicKey() throws SshException {
      return delegate.getPublicKey();
    }

    @Override
    public PublicKey getPublicKey(BufferPublicKeyParser<? extends PublicKey> parser)
        throws SshException {
      return delegate.getPublicKey(parser);
    }

    @Override
    public PublicKey getRawPublicKey() throws SshException {
      return delegate.getRawPublicKey();
    }

    @Override
    public PublicKey getRawPublicKey(BufferPublicKeyParser<? extends PublicKey> parser)
        throws SshException {
      return delegate.getRawPublicKey(parser);
    }

    @Override
    public KeyPair getKeyPair() throws SshException {
      return delegate.getKeyPair();
    }

    @Override
    public int ensureAvailable(int reqLen) throws BufferException {
      return delegate.ensureAvailable(reqLen);
    }

    @Override
    public void putByte(byte b) {
      delegate.putByte(b);
    }

    @Override
    public void putOptionalBufferedData(Object buffer) {
      delegate.putOptionalBufferedData(buffer);
    }

    @Override
    public void putBufferedData(Object buffer) {
      delegate.putBufferedData(buffer);
    }

    @Override
    public void putBuffer(Readable buffer) {
      delegate.putBuffer(buffer);
    }

    @Override
    public int putBuffer(Readable buffer, boolean expand) {
      return delegate.putBuffer(buffer, expand);
    }

    @Override
    public void putBuffer(ByteBuffer buffer) {
      delegate.putBuffer(buffer);
    }

    @Override
    public void putShort(int i) {
      delegate.putShort(i);
    }

    @Override
    public void putInt(long i) {
      delegate.putInt(i);
    }

    @Override
    public void putLong(long i) {
      delegate.putLong(i);
    }

    @Override
    public void putBoolean(boolean b) {
      delegate.putBoolean(b);
    }

    @Override
    public void putAndWipeBytes(byte[] b) {
      delegate.putAndWipeBytes(b);
    }

    @Override
    public void putAndWipeBytes(byte[] b, int off, int len) {
      delegate.putAndWipeBytes(b, off, len);
    }

    @Override
    public void putBytes(byte[] b) {
      delegate.putBytes(b);
    }

    @Override
    public void putBytes(byte[] b, int off, int len) {
      delegate.putBytes(b, off, len);
    }

    @Override
    public void putStringList(Collection<?> objects, boolean prependLength) {
      delegate.putStringList(objects, prependLength);
    }

    @Override
    public void putStringList(Collection<?> objects, Charset charset, boolean prependLength) {
      delegate.putStringList(objects, charset, prependLength);
    }

    @Override
    public void putNameList(Collection<String> names) {
      delegate.putNameList(names);
    }

    @Override
    public void putNameList(Collection<String> names, Charset charset) {
      delegate.putNameList(names, charset);
    }

    @Override
    public void putNameList(Collection<String> names, char separator) {
      delegate.putNameList(names, separator);
    }

    @Override
    public void putNameList(Collection<String> names, Charset charset, char separator) {
      delegate.putNameList(names, charset, separator);
    }

    @Override
    public void putString(String string) {
      delegate.putString(string);
    }

    @Override
    public void putString(String string, Charset charset) {
      delegate.putString(string, charset);
    }

    @Override
    public void putAndWipeChars(char[] chars) {
      delegate.putAndWipeChars(chars);
    }

    @Override
    public void putAndWipeChars(char[] chars, int offset, int len) {
      delegate.putAndWipeChars(chars, offset, len);
    }

    @Override
    public void putAndWipeChars(char[] chars, Charset charset) {
      delegate.putAndWipeChars(chars, charset);
    }

    @Override
    public void putAndWipeChars(char[] chars, int offset, int len, Charset charset) {
      delegate.putAndWipeChars(chars, offset, len, charset);
    }

    @Override
    public void putChars(char[] chars) {
      delegate.putChars(chars);
    }

    @Override
    public void putChars(char[] chars, int offset, int len) {
      delegate.putChars(chars, offset, len);
    }

    @Override
    public void putChars(char[] chars, Charset charset) {
      delegate.putChars(chars, charset);
    }

    @Override
    public void putChars(char[] chars, int offset, int len, Charset charset) {
      delegate.putChars(chars, offset, len, charset);
    }

    @Override
    public void putMPInt(BigInteger bi) {
      delegate.putMPInt(bi);
    }

    @Override
    public void putMPInt(byte[] foo) {
      delegate.putMPInt(foo);
    }

    @Override
    public void putRawBytes(byte[] d) {
      delegate.putRawBytes(d);
    }

    @Override
    public void putRawBytes(byte[] d, int off, int len) {
      delegate.putRawBytes(d, off, len);
    }

    @Override
    public void putPublicKey(PublicKey key) {
      delegate.putPublicKey(key);
    }

    @Override
    public void putRawPublicKey(PublicKey key) {
      delegate.putRawPublicKey(key);
    }

    @Override
    public void putRawPublicKeyBytes(PublicKey key) {
      delegate.putRawPublicKeyBytes(key);
    }

    @Override
    public void putKeyPair(KeyPair kp) {
      delegate.putKeyPair(kp);
    }

    @Override
    public Buffer ensureCapacity(int capacity, IntUnaryOperator growthFactor) {
      return delegate.ensureCapacity(capacity, growthFactor);
    }

    @Override
    public String toString() {
      return delegate.toString();
    }

  }

}
