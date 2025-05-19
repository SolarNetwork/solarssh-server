/* ==================================================================
 * AbstractSshdServer.java - 12/08/2020 3:04:17 PM
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

import static net.solarnetwork.codec.JsonUtils.getJSONString;
import static net.solarnetwork.solarssh.Globals.AUDIT_LOG;
import static net.solarnetwork.solarssh.Globals.DEFAULT_SN_HOST;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Map;

import javax.cache.Cache;

import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;

import net.solarnetwork.solarssh.Globals;
import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * Abstract base class for SolarSSH SSHD server instances.
 * 
 * @author matt
 * @version 1.2
 */
public abstract class AbstractSshdServer implements SessionListener, ChannelListener {

  /**
   * The default value for the {@code authTimeoutSecs} property.
   */
  public static final int DEFAULT_AUTH_TIMEOUT_SECS = 300;

  /** A server property key for the listening port. */
  public static final String PORT_KEY = "solarssh.port";

  protected final SshSessionDao sessionDao;

  private String snHost = DEFAULT_SN_HOST;
  private int port = -1;
  private int authTimeoutSecs = DEFAULT_AUTH_TIMEOUT_SECS;
  private Resource serverKeyResource;
  private String serverKeyPassword;
  private Cache<InetAddress, Byte> bruteForceDenyList;
  private int bruteForceMaxTries = 1;

  /** A class-level logger. */
  protected final Logger log = LoggerFactory.getLogger(getClass());

  /**
   * Constructor.
   * 
   * @param sessionDao
   *        the session DAO
   */
  public AbstractSshdServer(SshSessionDao sessionDao) {
    super();
    this.sessionDao = sessionDao;
  }

  /**
   * Create a default SolarSSH server with common configuration applied.
   * 
   * @return the new server instance
   */
  protected SshServer createServer() {
    SshServer s = SshServer.setUpDefaultServer();
    s.setPort(port);
    s.getProperties().put(PORT_KEY, port);

    try {
      FileKeyPairProvider keyPairProvider = new FileKeyPairProvider(
          serverKeyResource.getFile().toPath());
      keyPairProvider.setPasswordFinder(FilePasswordProvider.of(serverKeyPassword));
      s.setKeyPairProvider(keyPairProvider);
      log.info("Using SSH server key from {}", serverKeyResource);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    s.setForwardingFilter(new SshSessionForwardFilter(sessionDao));

    s.addSessionListener(this);
    s.addChannelListener(this);

    s.getProperties().put(CoreModuleProperties.AUTH_TIMEOUT.getName(), authTimeoutSecs * 1000L);

    if (bruteForceDenyList != null) {
      BruteForceDenyEventListener listener = new BruteForceDenyEventListener(bruteForceDenyList);
      listener.setMaxFails(bruteForceMaxTries);
      s.setIoServiceEventListener(listener);
    }

    return s;
  }

  /**
   * Create an audit event map.
   * 
   * @param session
   *        the session
   * @param eventName
   *        the event name
   * @return the map
   */
  protected Map<String, Object> auditEventMap(Session session, String eventName) {
    SshSession sess = sessionDao.findOne(session);
    return Globals.auditEventMap(session, sess, eventName);
  }

  /**
   * Log a session closed event.
   * 
   * @param session
   *        the session
   * @param auditEventName
   *        the audit event name
   * @param t
   *        an optional exception
   */
  protected void logSessionClosed(Session session, String auditEventName, Throwable t) {
    SshSession sess = sessionDao.findOne(session);
    String sessionId = (sess != null ? sess.getId() : session.getUsername());
    log.info("Session {} closed", sessionId);
    Map<String, Object> auditProps = auditEventMap(session, auditEventName);
    IoSession ioSession = session.getIoSession();
    if (ioSession != null) {
      auditProps.put("remoteAddress", ioSession.getRemoteAddress());
    }
    if (t != null) {
      auditProps.put("error", t.toString());
    }
    AUDIT_LOG.info(getJSONString(auditProps, "{}"));
  }

  @Override
  public void channelOpenSuccess(Channel channel) {
    log.debug("Channel {} open success", channel);
  }

  @Override
  public void channelOpenFailure(Channel channel, Throwable reason) {
    log.debug("Channel {} open failure", channel, reason);
  }

  @Override
  public void channelClosed(Channel channel, Throwable reason) {
    log.debug("Channel {} from session {} closed", channel, channel.getSession().getUsername(),
        reason);
  }

  /**
   * Get the port to listen for SSH connections on.
   * 
   * @return the port to listen on
   */
  public int getPort() {
    return port;
  }

  /**
   * Set the port to listen for SSH connections on.
   * 
   * @param port
   *        the port to listen on
   */
  public void setPort(int port) {
    this.port = port;
  }

  /**
   * Set the resource that holds the server key to use.
   * 
   * @param serverKeyResource
   *        the server key resource
   */
  public void setServerKeyResource(Resource serverKeyResource) {
    this.serverKeyResource = serverKeyResource;
  }

  /**
   * Set the password for the server key resource.
   * 
   * @param serverKeyPassword
   *        the server key password, or {@literal null} for no password
   */
  public void setServerKeyPassword(String serverKeyPassword) {
    this.serverKeyPassword = serverKeyPassword;
  }

  /**
   * Get the SolarNetwork host to use.
   * 
   * @return the host
   */
  public String getSnHost() {
    return snHost;
  }

  /**
   * Set the SolarNetwork host to use.
   * 
   * @param snHost
   *        the host
   * @throws IllegalArgumentException
   *         if {@code snHost} is {@literal null}
   */
  public void setSnHost(String snHost) {
    if (snHost == null) {
      throw new IllegalArgumentException("snHost must not be null");
    }
    this.snHost = snHost;
  }

  /**
   * Get the authorization timeout value, in seconds.
   * 
   * @return the timeout seconds
   */
  public int getAuthTimeoutSecs() {
    return authTimeoutSecs;
  }

  /**
   * Set the authorization timeout value, in seconds.
   * 
   * <p>
   * This must be large enough to allow for SolarNode devices to handle the
   * {@literal StartRemoteSsh} instruction.
   * </p>
   * 
   * @param authTimeoutSecs
   *        the timeout seconds
   */
  public void setAuthTimeoutSecs(int authTimeoutSecs) {
    this.authTimeoutSecs = authTimeoutSecs;
  }

  /**
   * Get the brute force deny list.
   * 
   * @return the deny list
   */
  public Cache<InetAddress, Byte> getBruteForceDenyList() {
    return bruteForceDenyList;
  }

  /**
   * Set the brute force deny list.
   * 
   * @param bruteForceDenyList
   *        the deny list to set
   */
  public void setBruteForceDenyList(Cache<InetAddress, Byte> bruteForceDenyList) {
    this.bruteForceDenyList = bruteForceDenyList;
  }

  /**
   * Get the brute force max tries.
   * 
   * @return the max tries
   */
  public int getBruteForceMaxTries() {
    return bruteForceMaxTries;
  }

  /**
   * Set the brute force max tries.
   * 
   * @param bruteForceMaxTries
   *        the count to set
   */
  public void setBruteForceMaxTries(int bruteForceMaxTries) {
    this.bruteForceMaxTries = bruteForceMaxTries;
  }

}
