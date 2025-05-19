/* ==================================================================
 * DefaultSolarSshdServer.java - Jun 11, 2017 3:42:49 PM
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

package net.solarnetwork.solarssh.impl;

import static net.solarnetwork.codec.JsonUtils.getJSONString;
import static net.solarnetwork.solarssh.Globals.AUDIT_LOG;

import java.io.IOException;
import java.net.SocketAddress;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.helpers.AbstractSession;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.CachingPublicKeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;

import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.service.SolarSshdService;

/**
 * Service to manage the SSH server.
 * 
 * @author matt
 * @version 1.2
 */
public class DefaultSolarSshdServer extends AbstractSshdServer implements SolarSshdService {

  private static final String AUDIT_NODE_CONNECT = "NODE-CONNECT";

  private static final String AUDIT_NODE_DISCONNECT = "NODE-DISCONNECT";

  /** The default port to listen on. */
  public static final int DEFAULT_LISTEN_PORT = 8022;

  private SshServer server;

  /**
   * Constructor.
   * 
   * @param sessionDao
   *        the session DAO to use
   */
  public DefaultSolarSshdServer(SshSessionDao sessionDao) {
    super(sessionDao);
    setPort(DEFAULT_LISTEN_PORT);
  }

  /**
   * Start the server.
   */
  public synchronized void start() {
    SshServer s = server;
    if (s != null) {
      return;
    }
    s = createServer();

    // TODO: verify if CachingPublicKeyAuthenticator is appropriate
    s.setPublickeyAuthenticator(
        new CachingPublicKeyAuthenticator(new SolarSshPublicKeyAuthenticator(sessionDao)));

    try {
      s.start();
    } catch (IOException e) {
      throw new RuntimeException("Communication error starting SSH server", e);
    }
    log.info("SSH server listening on port {}", getPort());
    server = s;
  }

  /**
   * Stop the server.
   */
  public synchronized void stop() {
    SshServer s = server;
    if (s != null && s.isOpen()) {
      try {
        s.removeSessionListener(this);
        s.removeChannelListener(this);
        s.stop();
      } catch (IOException e) {
        log.warn("Communication error stopping SSH server: {}", e.getMessage());
      }
    }
  }

  @Override
  public synchronized ServerSession serverSessionForSessionId(String sessionId) {
    if (server == null || !server.isOpen()) {
      return null;
    }
    List<AbstractSession> sessions = server.getActiveSessions();
    log.debug("{} active sessions: {}", sessions != null ? sessions.size() : 0, sessions);
    AbstractSession session = sessions.stream().filter(s -> sessionId.equals(s.getUsername()))
        .findFirst().orElse(null);
    return (ServerSession) session;
  }

  @Override
  public void sessionEvent(Session session, Event event) {
    if (event == SessionListener.Event.Authenticated) {
      String sessionId = session.getUsername();
      SshSession sess = sessionDao.findOne(sessionId);
      if (sess != null) {
        sess.setEstablished(true);
        sess.setServerSession(session);

        Map<String, Object> auditProps = sess.auditEventMap(AUDIT_NODE_CONNECT);
        auditProps.put("date", System.currentTimeMillis());
        IoSession ioSession = session.getIoSession();
        if (ioSession != null) {
          auditProps.put("remoteAddress", ioSession.getRemoteAddress());
        }
        auditProps.put("rport", sess.getReverseSshPort());
        AUDIT_LOG.info(getJSONString(auditProps, "{}"));
      }
    }
  }

  @Override
  public void sessionException(Session session, Throwable t) {
    String msg = t.getMessage();
    if (msg.contains("SSH_MSG_CHANNEL_EOF")) {
      // org.apache.sshd.common.SshException: Write attempt on closing session: SSH_MSG_CHANNEL_EOF
      // see https://github.com/apache/mina-sshd/issues/410
      // although marked as fixed, still seeing
      return;
    }
    log.warn("Session {} exception", session.getUsername(), t);
    logSessionClosed(session, AUDIT_NODE_DISCONNECT, t);
  }

  @Override
  public void sessionClosed(Session session) {
    String sessionId = session.getUsername();
    if (sessionId != null) {
      logSessionClosed(session, AUDIT_NODE_DISCONNECT, null);
      SshSession sess = sessionDao.findOne(sessionId);
      if (sess != null) {
        // check if matching remote address
        SocketAddress closedSessionRemoteAddress = null;
        SocketAddress daoSessionRemoteAddress = null;
        IoSession ioSession = session.getIoSession();
        if (ioSession != null) {
          closedSessionRemoteAddress = ioSession.getRemoteAddress();
        }
        Session daoServerSession = sess.getServerSession();
        if (daoServerSession != null) {
          IoSession daoIoSession = daoServerSession.getIoSession();
          if (daoIoSession != null) {
            daoSessionRemoteAddress = daoIoSession.getRemoteAddress();
          }
        }
        if (closedSessionRemoteAddress == null || daoSessionRemoteAddress == null
            || closedSessionRemoteAddress.equals(daoSessionRemoteAddress)) {
          sessionDao.delete(sess);
        }
      }
    }
  }

}
