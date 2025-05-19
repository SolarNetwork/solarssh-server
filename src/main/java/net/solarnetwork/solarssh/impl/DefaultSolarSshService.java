/* ==================================================================
 * DefaultSolarSshService.java - 16/06/2017 7:36:37 PM
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

import static net.solarnetwork.solarssh.Globals.AUDIT_LOG;
import static net.solarnetwork.solarssh.service.SolarNetClient.INSTRUCTION_TOPIC_START_REMOTE_SSH;
import static net.solarnetwork.solarssh.service.SolarNetClient.INSTRUCTION_TOPIC_STOP_REMOTE_SSH;
import static net.solarnetwork.solarssh.service.SolarNetClient.REVERSE_PORT_PARAM;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.SocketException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.io.input.NoCloseInputStream;
import org.apache.sshd.common.util.io.output.NoCloseOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.solarnetwork.codec.JsonUtils;
import net.solarnetwork.domain.datum.GeneralDatumMetadata;
import net.solarnetwork.service.PingTest;
import net.solarnetwork.service.PingTestResult;
import net.solarnetwork.solarssh.AuthorizationException;
import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SolarNetInstruction;
import net.solarnetwork.solarssh.domain.SolarNodeInstructionState;
import net.solarnetwork.solarssh.domain.SshCredentials;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.domain.SshTerminalSettings;
import net.solarnetwork.solarssh.service.SolarNetClient;
import net.solarnetwork.solarssh.service.SolarSshService;

/**
 * Default implementation of {@link SolarSshService}.
 * 
 * @author matt
 * @version 1.2
 */
public class DefaultSolarSshService implements SolarSshService, SshSessionDao, PingTest {

  private static final Logger log = LoggerFactory.getLogger(DefaultSolarSshService.class);

  private String host = "ssh.solarnetwork.net";
  private int port = 8022;
  private int minPort = 50000;
  private int maxPort = 65000;
  private int sessionExpireSeconds = 300;

  private final SolarNetClient solarNetClient;
  private final ConcurrentMap<Integer, SshSession> portSessionMap = new ConcurrentHashMap<>();
  private final ConcurrentMap<String, SshSession> sessionMap = new ConcurrentHashMap<>();

  /**
   * Constructor.
   * 
   * @param solarNetClient
   *        the SolarNetwork client to use
   */
  public DefaultSolarSshService(SolarNetClient solarNetClient) {
    super();
    this.solarNetClient = solarNetClient;
  }

  /**
   * Initialize the service after all properties configured.
   */
  public void init() {
    log.info("SolarSshService configured as host {}:{} using local ports {}:{}", host, port,
        minPort, maxPort);
  }

  @Override
  public String getPingTestId() {
    return "net.solarnetwork.solarssh.impl.DefaultSolarSshService";
  }

  @Override
  public long getPingTestMaximumExecutionMilliseconds() {
    return 1000;
  }

  @Override
  public String getPingTestName() {
    return "SolarSSH Service";
  }

  @Override
  public Result performPingTest() throws Exception {
    Map<String, Object> properties = new LinkedHashMap<>(8);
    StringBuilder msg = new StringBuilder();
    msg.append(host).append(":").append(port).append(" listening.");
    int sessionCount = 0;
    int activeCount = 0;
    for (SshSession session : sessionMap.values()) {
      sessionCount++;
      if (session.isEstablished()) {
        activeCount++;
      }
    }
    properties.put("sessionCount", sessionCount);
    properties.put("activeSessionCount", activeCount);
    msg.append(" ").append(sessionCount).append(" sessions (").append(activeCount)
        .append(" active).");
    return new PingTestResult(true, msg.toString(), properties);
  }

  @Override
  public SshSession findOne(String id) {
    if (id == null) {
      throw new IllegalArgumentException("Null value not allowed.");
    }
    return sessionMap.get(id);
  }

  @Override
  public SshSession findOne(final Session session) {
    if (session == null) {
      throw new IllegalArgumentException("Null value not allowed.");
    }
    return sessionMap.values().stream().filter(e -> {
      return e.getServerSession() == session || e.getDirectServerSession() == session
          || e.getClientSession() == session;
    }).findAny().orElse(null);
  }

  @Override
  public void delete(SshSession sess) {
    if (sess == null) {
      throw new IllegalArgumentException("Null value not allowed.");
    }
    endSession(sess);
    portSessionMap.remove(sess.getReverseSshPort(), sess);
    sessionMap.remove(sess.getId(), sess);
  }

  @Override
  public SshSession createNewSession(Long nodeId, long authorizationDate, String authorization)
      throws IOException {
    // see if instruction for StartRemoteSsh already pending, and if so can return session 
    // with that instruction ID
    List<SolarNetInstruction> instructions = solarNetClient.pendingInstructions(nodeId,
        authorizationDate, authorization);
    SolarNetInstruction pending = instructions.stream()
        .filter(instr -> nodeId.equals(instr.getNodeId())).findAny().orElse(null);
    if (pending != null) {
      SshSession sess = portSessionMap.values().stream()
          .filter(s -> pending.getId().equals(s.getStartInstructionId())).findAny().orElse(null);
      if (sess != null) {
        log.info("Returning existing SshSession {} already in {} state", sess.getId(),
            pending.getState());
        return sess;
      }
    }

    String sessionId = UUID.randomUUID().toString();
    Set<Integer> usedPorts = portSessionMap.keySet();

    for (int rport = minPort; rport < maxPort; rport += 2) {
      if (usedPorts.contains(rport)) {
        continue;
      }
      try (ServerSocket socket = new ServerSocket(rport)) {
        socket.setReuseAddress(true);
        try (ServerSocket httpSocket = new ServerSocket(rport + 1)) {
          httpSocket.setReuseAddress(true);
          SshSession sess = new SshSession(System.currentTimeMillis(), sessionId, nodeId, host,
              port, rport, rport + 1);
          if (portSessionMap.putIfAbsent(rport, sess) == null) {
            sessionMap.put(sessionId, sess);
            log.info("SshSession {} created: node {}, rport {}", sessionId, nodeId, rport);
            Map<String, Object> auditProps = sess.auditEventMap("NEW");
            auditProps.put("date", sess.getCreated());
            auditProps.put(REVERSE_PORT_PARAM, rport);
            AUDIT_LOG.info(JsonUtils.getJSONString(auditProps, "{}"));
            return sess;
          }
        } catch (SocketException e) {
          // ignore this one
        }
      } catch (SocketException e) {
        // ignore this one
      }
    }
    throw new IOException("No available port found.");
  }

  @Override
  public SolarNodeInstructionState getInstructionState(Long id, long authorizationDate,
      String authorization) throws IOException {
    SolarNetInstruction instr = solarNetClient.getInstruction(id, authorizationDate, authorization);
    return (instr != null ? instr.getState() : SolarNodeInstructionState.Unknown);
  }

  @Override
  public SshSession startSession(String sessionId, long authorizationDate, String authorization)
      throws IOException {
    SshSession sess = sessionMap.get(sessionId);
    if (sess == null) {
      throw new AuthorizationException("Session " + sessionId + " not available");
    }

    Map<String, String> instructionParams = SolarNetClient.createRemoteSshInstructionParams(sess);

    Long instructionId = solarNetClient.queueInstruction(INSTRUCTION_TOPIC_START_REMOTE_SSH,
        sess.getNodeId(), instructionParams, authorizationDate, authorization);

    if (instructionId == null) {
      throw new AuthorizationException(
          "Unable to queue StartRemoteSsh instruction for session " + sessionId);
    }

    sess.setStartInstructionId(instructionId);
    return sess;
  }

  @Override
  public SshSession attachTerminal(String sessionId, long authorizationDate, String authorization,
      SshCredentials nodeCredentials, SshTerminalSettings settings, InputStream in,
      OutputStream out) throws IOException {
    SshSession sess = sessionMap.get(sessionId);
    if (sess == null) {
      throw new AuthorizationException("Session " + sessionId + " not available");
    }
    GeneralDatumMetadata meta = solarNetClient.getNodeMetadata(sess.getNodeId(), authorizationDate,
        authorization);
    log.debug("Got node {} metadata info: {}", sess.getNodeId(), meta.getInfo());

    // TODO: extract node public key? by doing nothing, we have at least verified the 
    //       caller has authorization as a user for this node...

    ClientSession clientSession = createClient(sess, nodeCredentials, settings, in, out);
    sess.setClientSession(clientSession);

    Map<String, Object> auditProps = sess.auditEventMap("ATTACH-TERM");
    auditProps.put("date", System.currentTimeMillis());
    auditProps.put("connectAddress", clientSession.getConnectAddress());
    AUDIT_LOG.info(JsonUtils.getJSONString(auditProps, "{}"));

    return sess;
  }

  private ClientSession createClient(SshSession sess, SshCredentials credentials,
      SshTerminalSettings settings, InputStream in, OutputStream out) throws IOException {
    SshClient client = SshClient.setUpDefaultClient();
    client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY); // no need
    client.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER); // no need
    client.start();

    ClientSession session = client
        .connect(credentials.getUsername(), "127.0.0.1", sess.getReverseSshPort())
        .verify(30, TimeUnit.SECONDS).getSession();
    if (credentials.getPassword() != null) {
      session.addPasswordIdentity(credentials.getPassword());
    }

    session.auth().verify(30, TimeUnit.SECONDS);

    ChannelShell channel = session.createShellChannel();

    if (settings != null) {
      if (settings.getType() != null) {
        channel.setPtyType(settings.getType());
      }
      channel.setPtyColumns(settings.getCols());
      channel.setPtyLines(settings.getLines());
      channel.setPtyWidth(settings.getWidth());
      channel.setPtyHeight(settings.getHeight());
      settings.getEnvironment().forEach((k, v) -> channel.setEnv(k, v));
    }

    channel.addCloseFutureListener(new SshFutureListener<CloseFuture>() {

      @Override
      public void operationComplete(CloseFuture future) {
        sess.setClientSession(null);
        try {
          out.close();
        } catch (IOException e) {
          log.debug("Error closing SSH output stream: {}", e.getMessage());
        } finally {
          Map<String, Object> auditProps = sess.auditEventMap("DETACH-TERM");
          auditProps.put("date", System.currentTimeMillis());
          AUDIT_LOG.info(JsonUtils.getJSONString(auditProps, "{}"));
        }
      }
    });
    channel.setIn(new NoCloseInputStream(in));

    OutputStream channelOut = new NoCloseOutputStream(out);
    channel.setOut(channelOut);
    channel.setErr(channelOut);
    channel.open().verify(30, TimeUnit.SECONDS);

    return session;
  }

  @Override
  public SshSession stopSession(String sessionId, long authorizationDate, String authorization)
      throws IOException {
    SshSession sess = sessionMap.get(sessionId);
    if (sess == null) {
      throw new AuthorizationException("Session " + sessionId + " not available");
    }

    Map<String, String> instructionParams = SolarNetClient.createRemoteSshInstructionParams(sess);

    Long instructionId = solarNetClient.queueInstruction(INSTRUCTION_TOPIC_STOP_REMOTE_SSH,
        sess.getNodeId(), instructionParams, authorizationDate, authorization);

    if (instructionId == null) {
      throw new AuthorizationException(
          "Unable to queue StopRemoteSsh instruction for session " + sessionId);
    }

    sess.setStopInstructionId(instructionId);
    delete(sess);
    return sess;
  }

  private void endSession(SshSession sess) {
    if (sess == null) {
      return;
    }
    ClientSession clientSession = sess.getClientSession();
    if (clientSession != null) {
      clientSession.close(false);
      sess.setClientSession(null);
    }
    Session serverSession = sess.getServerSession();
    if (serverSession != null) {
      serverSession.close(false);
      sess.setServerSession(null);
    }
    if (sess.isEstablished()) {
      log.debug("Ended session {}", sess.getId());
      long now = System.currentTimeMillis();
      long secs = (long) Math.ceil((now - sess.getCreated()) / 1000.0);
      Map<String, Object> auditProps = sess.auditEventMap("END");
      auditProps.put("date", now);
      auditProps.put("duration", secs);
      AUDIT_LOG.info(JsonUtils.getJSONString(auditProps, "{}"));
      sess.setEstablished(false);
    }
  }

  /**
   * Call periodically to free expired sessions.
   */
  public void cleanupExpiredSessions() {
    final long expireTime = System.currentTimeMillis()
        - TimeUnit.SECONDS.toMillis(sessionExpireSeconds);
    if (log.isDebugEnabled()) {
      log.debug("Examining {} sessions for expiration", portSessionMap.size());
    }
    for (Iterator<SshSession> itr = portSessionMap.values().iterator(); itr.hasNext();) {
      SshSession sess = itr.next();
      if (!sess.isEstablished() && sess.getCreated() < expireTime) {
        log.info("Expiring unestablished SshSession {}: node {}, rport {}", sess.getId(),
            sess.getNodeId(), sess.getReverseSshPort());
        endSession(sess);
        itr.remove();
        sessionMap.remove(sess.getId(), sess);
      }
    }
  }

  public void setMinPort(int minPort) {
    this.minPort = minPort;
  }

  public void setMaxPort(int maxPort) {
    this.maxPort = maxPort;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public void setPort(int port) {
    this.port = port;
  }

  public void setSessionExpireSeconds(int sessionExpireSeconds) {
    this.sessionExpireSeconds = sessionExpireSeconds;
  }

}
