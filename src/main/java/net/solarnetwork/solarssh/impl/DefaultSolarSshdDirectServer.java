/* ==================================================================
 * DefaultSolarSshdDirectServer.java - 11/08/2020 6:59:41 AM
 * 
 * Copyright 2020 SolarNetwork SolarNetwork.net Dev Team
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

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static net.solarnetwork.codec.JsonUtils.getJSONString;
import static net.solarnetwork.solarssh.Globals.AUDIT_LOG;
import static net.solarnetwork.solarssh.service.SolarNetClient.INSTRUCTION_TOPIC_STOP_REMOTE_SSH;

import java.io.IOException;
import java.net.SocketAddress;
import java.time.Instant;
import java.util.Map;

import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import net.solarnetwork.security.Snws2AuthorizationBuilder;
import net.solarnetwork.solarssh.dao.ActorDao;
import net.solarnetwork.solarssh.domain.DirectSshUsername;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.service.SolarNetClient;
import net.solarnetwork.solarssh.service.SolarSshService;

/**
 * Default SSH server service.
 * 
 * @author matt
 * @version 1.1
 */
public class DefaultSolarSshdDirectServer extends AbstractSshdServer {

  private static final String AUDIT_DIRECT_CONNECT = "DIRECT-CONNECT";

  private static final String AUDIT_DIRECT_DISCONNECT = "DIRECT-DISCONNECT";

  /** The default port to listen on. */
  public static final int DEFAULT_LISTEN_PORT = 9022;

  private final SolarSshService solarSshService;
  private final ActorDao actorDao;

  // CHECKSTYLE OFF: LineLength
  private long instructionCompletedWaitMs = SolarSshPasswordAuthenticator.DEFAULT_INSTRUCTION_COMPLETED_WAIT_MS;
  private long instructionIncompleteWaitMs = SolarSshPasswordAuthenticator.DEFAULT_INSTRUCTION_INCOMPLETED_WAIT_MS;
  // CHECKSTYLE OFF: LineLength

  private SshServer server;

  /**
   * Constructor.
   * 
   * @param solarSshService
   *        the SolarSshService to use
   * @param actorDao
   *        the actor DAO to use
   */
  public DefaultSolarSshdDirectServer(SolarSshService solarSshService, ActorDao actorDao) {
    super(solarSshService);
    this.solarSshService = solarSshService;
    this.actorDao = actorDao;
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

    s.setChannelFactories(unmodifiableList(
        asList(ChannelSessionFactory.INSTANCE, new DynamicDirectTcpipFactory(sessionDao))));

    SolarSshPasswordAuthenticator pwAuth = new SolarSshPasswordAuthenticator(solarSshService,
        actorDao);
    pwAuth.setSnHost(getSnHost());
    pwAuth.setInstructionCompletedWaitMs(instructionCompletedWaitMs);
    pwAuth.setInstructionIncompleteWaitMs(instructionIncompleteWaitMs);
    pwAuth.setMaxNodeInstructionWaitSecs(getAuthTimeoutSecs());

    PasswordAuthenticator auth = pwAuth;
    if (getBruteForceDenyList() != null) {
      BruteForceDenyPasswordAuthenticator bf = new BruteForceDenyPasswordAuthenticator(pwAuth,
          getBruteForceDenyList());
      bf.setMaxFails(getBruteForceMaxTries());
      auth = bf;
    }
    s.setPasswordAuthenticator(auth);

    try {
      s.start();
    } catch (IOException e) {
      throw new RuntimeException("Communication error starting SSH server on port " + getPort(), e);
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
  public void sessionEvent(Session session, Event event) {
    if (event == SessionListener.Event.Authenticated) {
      SshSession sess = sessionDao.findOne(session);
      if (sess != null) {
        if (!sess.isEstablished()) {
          sess.setEstablished(true);
          sess.setDirectServerSession(session);
        }

        Map<String, Object> auditProps = sess.auditEventMap(AUDIT_DIRECT_CONNECT);
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
    log.debug("Session {} exception", session.getUsername(), t);
    logSessionClosed(session, AUDIT_DIRECT_DISCONNECT, t);
  }

  @Override
  public void sessionClosed(Session session) {
    String username = session.getUsername();
    if (username != null) {
      logSessionClosed(session, AUDIT_DIRECT_DISCONNECT, null);
      SshSession sess = sessionDao.findOne(session);
      if (sess != null) {
        // check if matching remote address
        SocketAddress closedSessionRemoteAddress = null;
        SocketAddress daoSessionRemoteAddress = null;
        IoSession ioSession = session.getIoSession();
        if (ioSession != null) {
          closedSessionRemoteAddress = ioSession.getRemoteAddress();
        }
        Session daoServerSession = sess.getDirectServerSession();
        if (daoServerSession != null) {
          IoSession daoIoSession = daoServerSession.getIoSession();
          if (daoIoSession != null) {
            daoSessionRemoteAddress = daoIoSession.getRemoteAddress();
          }
        }
        if (closedSessionRemoteAddress == null || daoSessionRemoteAddress == null
            || closedSessionRemoteAddress.equals(daoSessionRemoteAddress)) {
          try {
            stopRemoteSsh(username, sess);
          } finally {
            sessionDao.delete(sess);
          }
        }
      }
    }
  }

  private void stopRemoteSsh(String username, SshSession sshSession) {
    if (username == null || sshSession == null || sshSession.getTokenSecret() == null) {
      return;
    }
    DirectSshUsername directUsername;
    try {
      directUsername = DirectSshUsername.valueOf(username);
    } catch (IllegalArgumentException e) {
      return;
    }
    Map<String, String> instructionParams = SolarNetClient
        .createRemoteSshInstructionParams(sshSession);
    instructionParams.put("nodeId", directUsername.getNodeId().toString());
    instructionParams.put("topic", INSTRUCTION_TOPIC_STOP_REMOTE_SSH);

    Instant now = Instant.now();
    Snws2AuthorizationBuilder authBuilder = new Snws2AuthorizationBuilder(
        directUsername.getTokenId()).saveSigningKey(sshSession.getTokenSecret()).date(now)
            .host(getSnHost()).method(HttpMethod.POST.toString())
            .path("/solaruser/api/v1/sec/instr/add")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .queryParams(instructionParams);

    try {
      sshSession = solarSshService.stopSession(sshSession.getId(), now.toEpochMilli(),
          authBuilder.build());
      log.info("Issued {} instruction for token {} node {} with parameters {}",
          INSTRUCTION_TOPIC_STOP_REMOTE_SSH, directUsername.getTokenId(),
          directUsername.getNodeId(), instructionParams);
    } catch (IOException e) {
      log.warn("Communication error issuing StopRemoteSsh instruction: {}", e.toString());
    }
  }

  /**
   * Set the number of milliseconds to wait after a node instruction has completed before
   * continuing.
   * 
   * <p>
   * This is designed to give the node a bit of time to actually establish its SSH connection to the
   * SolarSSH server after reporting that it has completed the {@literal StartRemoteSsh}
   * instruction. It can take a few seconds for that to happen, especially on slow network
   * connections.
   * </p>
   * 
   * @param instructionCompletedWaitMs
   *        the wait time, in milliseconds; defaults to
   *        {@link #DEFAULT_INSTRUCTION_COMPLETED_WAIT_MS}
   */
  public void setInstructionCompletedWaitMs(long instructionCompletedWaitMs) {
    this.instructionCompletedWaitMs = instructionCompletedWaitMs;
  }

  /**
   * Set the number of milliseconds to wait after checking for a node instruction to complete when
   * discovered the instruction is not complete yet, before checking the instruction status again.
   * 
   * @param instructionIncompleteWaitMs
   *        the wait time, in milliseconds; defaults to
   *        {@link #DEFAULT_INSTRUCTION_INCOMPLETED_WAIT_MS}
   */
  public void setInstructionIncompleteWaitMs(long instructionIncompleteWaitMs) {
    this.instructionIncompleteWaitMs = instructionIncompleteWaitMs;
  }

}
