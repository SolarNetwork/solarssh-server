/* ==================================================================
 * SolarSshServersIntegrationTests.java - 8/10/2026 8:30:00 PM
 *
 * Copyright 2026 SolarNetwork.net Dev Team
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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;
import static net.solarnetwork.solarssh.service.SolarNetClient.INSTRUCTION_TOPIC_START_REMOTE_SSH;
import static net.solarnetwork.solarssh.service.SolarNetClient.INSTRUCTION_TOPIC_STOP_REMOTE_SSH;
import static net.solarnetwork.solarssh.service.SolarNetClient.REVERSE_PORT_PARAM;
import static net.solarnetwork.solarssh.service.SolarNetClient.USER_PARAM;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.password.UserAuthPassword;
import org.apache.sshd.client.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSession.ClientSessionEvent;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyEncryptionContext;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.command.AbstractCommandSupport;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.FileSystemResource;

import net.solarnetwork.domain.datum.GeneralDatumMetadata;
import net.solarnetwork.solarssh.AuthorizationException;
import net.solarnetwork.solarssh.dao.ActorDao;
import net.solarnetwork.solarssh.dao.SolarNodeDao;
import net.solarnetwork.solarssh.domain.Actor;
import net.solarnetwork.solarssh.domain.SolarNetInstruction;
import net.solarnetwork.solarssh.domain.SolarNodeInstructionState;
import net.solarnetwork.solarssh.domain.SshCredentials;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.service.SolarNetClient;

/**
 * Integration tests for the node and direct SSH servers, using MINA SSH clients to play both the
 * node and the direct SSH client.
 *
 * <p>
 * The SolarNetwork API is mocked: queueing a {@literal StartRemoteSsh} instruction makes the
 * simulated node connect and open its reverse tunnel to a local echo service.
 * </p>
 *
 * @author matt
 * @version 1.0
 */
public class SolarSshServersIntegrationTests {

  private static final String KEY_PASSWORD = "test";
  private static final Long NODE_ID = 123L;
  private static final String TOKEN_ID = "token";
  private static final String TOKEN_SECRET = "secret";
  private static final String DIRECT_USERNAME = NODE_ID + ":" + TOKEN_ID;
  private static final long TIMEOUT_SECS = 10;
  private static final String NODE_SHELL_USERNAME = "solar";
  private static final String NODE_SHELL_PASSWORD = "solar";
  private static final Pattern SSH_CLIENT_THREAD_NAME = Pattern
      .compile("sshd-SshClient\\[(\\w+)\\]");

  @TempDir
  private Path tmpDir;

  private final List<ClientSession> nodeSessions = new CopyOnWriteArrayList<>();
  private final AtomicLong instructionIds = new AtomicLong();
  private volatile boolean nodeResponds = true;
  private KeyPair nodeKey;
  private ExecutorService executor;
  private ServerSocket echoServer;
  private SolarNetClient solarNetClient;
  private DefaultSolarSshService service;
  private DefaultSolarSshdServer nodeServer;
  private DefaultSolarSshdDirectServer directServer;
  private SshServer nodeShellServer;
  private SshClient client;
  private int nodePort;
  private int directPort;

  @BeforeEach
  public void setup() throws Exception {
    executor = Executors.newCachedThreadPool();
    echoServer = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    executor.execute(this::echo);

    client = SshClient.setUpDefaultClient();
    client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);
    client.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
    // like OpenSSH on a node, accept the forwarded-tcpip channels of the reverse tunnel
    client.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
    client.start();

    solarNetClient = mock(SolarNetClient.class);
    given(solarNetClient.queueInstruction(eq(INSTRUCTION_TOPIC_START_REMOTE_SSH), eq(NODE_ID),
        any(), anyLong(), anyString())).willAnswer(invocation -> {
          // like a node, connect after receiving the instruction
          Map<String, ?> params = invocation.getArgument(2);
          String sessionId = instructionParam(params, USER_PARAM);
          int rport = Integer.parseInt(instructionParam(params, REVERSE_PORT_PARAM));
          if (nodeResponds) {
            executor.execute(() -> connectNode(sessionId, rport));
          }
          return instructionIds.incrementAndGet();
        });
    given(solarNetClient.queueInstruction(eq(INSTRUCTION_TOPIC_STOP_REMOTE_SSH), eq(NODE_ID), any(),
        anyLong(), anyString())).willAnswer(invocation -> instructionIds.incrementAndGet());
    given(solarNetClient.getNodeMetadata(eq(NODE_ID), anyLong(), anyString()))
        .willReturn(new GeneralDatumMetadata());
    given(solarNetClient.getInstruction(anyLong(), anyLong(), anyString()))
        .willAnswer(invocation -> {
          SolarNetInstruction instr = new SolarNetInstruction();
          instr.setId(invocation.getArgument(0));
          instr.setState(SolarNodeInstructionState.Completed);
          return instr;
        });

    nodePort = freePort();
    directPort = freePort();
    final int minPort = 2 * ThreadLocalRandom.current().nextInt(20000, 29000);

    service = new DefaultSolarSshService(solarNetClient);
    service.setHost("127.0.0.1");
    service.setPort(nodePort);
    service.setMinPort(minPort);
    service.setMaxPort(minPort + 200);

    // like a node, publish the public key it authenticates with
    nodeKey = newKeyPair();
    SolarNodeDao nodeDao = mock(SolarNodeDao.class);
    given(nodeDao.findSshPublicKey(NODE_ID))
        .willReturn(PublicKeyEntry.toString(nodeKey.getPublic()) + " solar@solarnode");

    FileSystemResource hostKey = new FileSystemResource(writeHostKey());

    nodeServer = new DefaultSolarSshdServer(service);
    nodeServer.setPort(nodePort);
    nodeServer.setServerKeyResource(hostKey);
    nodeServer.setServerKeyPassword(KEY_PASSWORD);
    nodeServer.setNodeDao(nodeDao);
    nodeServer.start();

    ActorDao actorDao = mock(ActorDao.class);
    given(actorDao.getAuthenticatedActor(NODE_ID, TOKEN_ID, TOKEN_SECRET))
        .willReturn(mock(Actor.class));

    directServer = new DefaultSolarSshdDirectServer(service, actorDao);
    directServer.setPort(directPort);
    directServer.setServerKeyResource(hostKey);
    directServer.setServerKeyPassword(KEY_PASSWORD);
    directServer.setAuthTimeoutSecs((int) TIMEOUT_SECS);
    directServer.setInstructionCompletedWaitMs(50);
    directServer.setInstructionIncompleteWaitMs(50);
    directServer.start();
  }

  /**
   * Stop the clients and servers.
   * 
   * @throws IOException
   *         if the echo service fails to close
   */
  @AfterEach
  public void teardown() throws IOException {
    service.shutdown();
    if (nodeShellServer != null) {
      nodeShellServer.stop();
    }
    client.stop();
    directServer.stop();
    nodeServer.stop();
    echoServer.close();
    executor.shutdownNow();
  }

  private Path writeHostKey() throws IOException, GeneralSecurityException {
    OpenSSHKeyEncryptionContext encryption = new OpenSSHKeyEncryptionContext();
    encryption.setPassword(KEY_PASSWORD);
    encryption.setCipherType("256");
    Path path = tmpDir.resolve("sshd-server-key");
    try (OutputStream out = Files.newOutputStream(path)) {
      OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(newKeyPair(), "test", encryption, out);
    }
    return path;
  }

  private static KeyPair newKeyPair() throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    return generator.generateKeyPair();
  }

  private static int freePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      return socket.getLocalPort();
    }
  }

  private static String instructionParam(Map<String, ?> params, String name) {
    for (Map.Entry<String, ?> e : params.entrySet()) {
      if (e.getKey().endsWith(".name") && name.equals(e.getValue())) {
        return params.get(e.getKey().replace(".name", ".value")).toString();
      }
    }
    return null;
  }

  private void echo() {
    while (!echoServer.isClosed()) {
      try {
        Socket socket = echoServer.accept();
        executor.execute(() -> {
          try (socket) {
            socket.getInputStream().transferTo(socket.getOutputStream());
          } catch (IOException e) {
            // connection closed
          }
        });
      } catch (IOException e) {
        return;
      }
    }
  }

  private ClientSession connectNode(String sessionId, int rport) {
    return connectNode(sessionId, rport, nodeKey);
  }

  private ClientSession connectNode(String sessionId, int rport, KeyPair key) {
    return connectNode(sessionId, rport, key, echoServer.getLocalPort());
  }

  private ClientSession connectNode(String sessionId, int rport, KeyPair key, int targetPort) {
    try {
      ClientSession node = client.connect(sessionId, "127.0.0.1", nodePort)
          .verify(TIMEOUT_SECS, SECONDS).getSession();
      nodeSessions.add(node);
      node.addPublicKeyIdentity(key);
      node.auth().verify(TIMEOUT_SECS, SECONDS);
      node.startRemotePortForwarding(new SshdSocketAddress("127.0.0.1", rport),
          new SshdSocketAddress("127.0.0.1", targetPort));
      return node;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Start an SSH server playing the node's own SSH daemon, with an echo shell that exits on an
   * {@literal exit} line.
   */
  private SshServer startNodeShellServer() throws IOException, GeneralSecurityException {
    nodeShellServer = SshServer.setUpDefaultServer();
    nodeShellServer.setHost("127.0.0.1");
    nodeShellServer.setPort(0);
    nodeShellServer.setKeyPairProvider(KeyPairProvider.wrap(newKeyPair()));
    nodeShellServer.setPasswordAuthenticator((username, password, session) -> {
      return NODE_SHELL_USERNAME.equals(username) && NODE_SHELL_PASSWORD.equals(password);
    });
    nodeShellServer.setShellFactory(channel -> new AbstractCommandSupport("echo", null) {

      @Override
      public void run() {
        try {
          BufferedReader in = new BufferedReader(
              new InputStreamReader(getInputStream(), UTF_8));
          String line;
          while ((line = in.readLine()) != null && !"exit".equals(line)) {
            getOutputStream().write((line + "\n").getBytes(UTF_8));
            getOutputStream().flush();
          }
          onExit(0);
        } catch (IOException e) {
          onExit(1, e.getMessage());
        }
      }
    });
    nodeShellServer.start();
    return nodeShellServer;
  }

  private SshSession attachNodeShell(SshSession sess, String password, PipedOutputStream terminalIn,
      OutputStream terminalOut) throws IOException {
    return service.attachTerminal(sess.getId(), Instant.now().toEpochMilli(), "auth",
        new SshCredentials(NODE_SHELL_USERNAME, password), null,
        new PipedInputStream(terminalIn), terminalOut);
  }

  private static String echoLine(OutputStream out, BufferedReader in, String line)
      throws IOException {
    out.write((line + "\n").getBytes(UTF_8));
    out.flush();
    return in.readLine();
  }

  private static void assertEventually(BooleanSupplier condition, String message)
      throws InterruptedException {
    final long expire = System.currentTimeMillis() + SECONDS.toMillis(TIMEOUT_SECS);
    while (!condition.getAsBoolean()) {
      if (System.currentTimeMillis() > expire) {
        fail(message);
      }
      Thread.sleep(50);
    }
  }

  /**
   * Count the started SSH clients, by the distinct client names in their thread names.
   *
   * <p>
   * A started client keeps at least a timer thread alive until it is stopped. Counting clients
   * rather than threads ignores the shared I/O pools, which start threads lazily up to a size
   * based on the number of CPU cores.
   * </p>
   *
   * @return the number of started SSH clients
   */
  private static long sshClientCount() {
    return Thread.getAllStackTraces().keySet().stream()
        .map(t -> SSH_CLIENT_THREAD_NAME.matcher(t.getName())).filter(Matcher::lookingAt)
        .map(m -> m.group(1)).distinct().count();
  }

  private int sessionCount() {
    try {
      return (Integer) service.performPingTest().getProperties().get("sessionCount");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private ClientSession connectDirect(SshClient sshClient) throws IOException {
    ClientSession session = sshClient.connect(DIRECT_USERNAME, "127.0.0.1", directPort)
        .verify(TIMEOUT_SECS, SECONDS).getSession();
    session.addPasswordIdentity(TOKEN_SECRET);
    return session;
  }

  /**
   * Assert that the client's node session has ended: the session is deleted, the node is asked to
   * stop, and the node's connection is closed.
   */
  private void assertNodeSessionEnded(String sessionId) throws Exception {
    assertEventually(() -> service.findOne(sessionId) == null, "Session deleted");
    assertEquals(0, sessionCount(), "No other sessions remain");
    assertEventually(() -> nodeSessions.stream().noneMatch(ClientSession::isOpen),
        "Node connection closed");
    then(solarNetClient).should().queueInstruction(eq(INSTRUCTION_TOPIC_STOP_REMOTE_SSH),
        eq(NODE_ID), any(), anyLong(), anyString());
  }

  @Test
  public void postQuantumKeyExchange() throws Exception {
    SshClient pqClient = SshClient.setUpDefaultClient();
    pqClient.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);
    pqClient.setKeyExchangeFactories(NamedFactory.setUpTransformedFactories(false,
        List.of(BuiltinDHFactories.mlkem768x25519), ClientBuilder.DH2KEX));
    pqClient.start();
    try (ClientSession session = connectDirect(pqClient)) {
      session.waitFor(EnumSet.of(ClientSessionEvent.WAIT_AUTH, ClientSessionEvent.CLOSED),
          SECONDS.toMillis(TIMEOUT_SECS));
      assertEquals("mlkem768x25519-sha256",
          session.getNegotiatedKexParameter(KexProposalOption.ALGORITHMS),
          "ML-KEM negotiated, which requires a compatible Bouncy Castle version");
    } finally {
      pqClient.stop();
    }
  }

  @Test
  public void nodeReverseTunnel() throws Exception {
    // GIVEN
    SshSession sess = service.createNewSession(NODE_ID, Instant.now().toEpochMilli(), "auth");

    // WHEN
    ClientSession node = connectNode(sess.getId(), sess.getReverseSshPort());

    // THEN
    assertEventually(() -> sess.getServerSession() != null, "Node session bound");
    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), sess.getReverseSshPort());
        BufferedReader in = new BufferedReader(
            new InputStreamReader(socket.getInputStream(), UTF_8))) {
      assertEquals("ping", echoLine(socket.getOutputStream(), in, "ping"),
          "Reverse tunnel reaches node");
    }
    assertThrows(IOException.class,
        () -> node.startRemotePortForwarding(
            new SshdSocketAddress("127.0.0.1", sess.getReverseSshPort() + 2),
            new SshdSocketAddress("127.0.0.1", echoServer.getLocalPort())),
        "Node may not listen outside of its reserved ports");
    assertThrows(RuntimeException.class,
        () -> connectNode("not-a-session", sess.getReverseSshPort()),
        "Unknown session ID rejected");
  }

  @Test
  public void nodeUnpublishedKey() throws Exception {
    // GIVEN
    SshSession sess = service.createNewSession(NODE_ID, Instant.now().toEpochMilli(), "auth");

    // THEN
    assertThrows(RuntimeException.class,
        () -> connectNode(sess.getId(), sess.getReverseSshPort(), newKeyPair()),
        "Key the node has not published rejected");
    assertNull(sess.getServerSession(), "Node session not bound");
    assertNotNull(service.findOne(sess.getId()), "Session still available to the real node");
  }

  @Test
  public void stopSessionConcurrentlyQueuesOneInstruction() throws Exception {
    // GIVEN
    SshSession sess = service.createNewSession(NODE_ID, Instant.now().toEpochMilli(), "auth");
    connectNode(sess.getId(), sess.getReverseSshPort());
    assertEventually(() -> sess.getServerSession() != null, "Node session bound");
    // hold the first stop while it queues the instruction, like a slow SolarNetwork request
    CountDownLatch queueing = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    given(solarNetClient.queueInstruction(eq(INSTRUCTION_TOPIC_STOP_REMOTE_SSH), eq(NODE_ID), any(),
        anyLong(), anyString())).willAnswer(invocation -> {
          queueing.countDown();
          release.await(TIMEOUT_SECS, SECONDS);
          return instructionIds.incrementAndGet();
        });
    final Future<SshSession> first = executor
        .submit(() -> service.stopSession(sess.getId(), Instant.now().toEpochMilli(), "auth"));
    assertTrue(queueing.await(TIMEOUT_SECS, SECONDS), "First stop queueing instruction");

    // WHEN
    assertThrows(AuthorizationException.class,
        () -> service.stopSession(sess.getId(), Instant.now().toEpochMilli(), "auth"),
        "Session being stopped is not available to stop again");
    release.countDown();

    // THEN
    assertSame(sess, first.get(TIMEOUT_SECS, SECONDS), "First stop completes");
    assertNodeSessionEnded(sess.getId());
  }

  @Test
  public void stopSessionAgainAfterQueueFailure() throws Exception {
    // GIVEN
    SshSession sess = service.createNewSession(NODE_ID, Instant.now().toEpochMilli(), "auth");
    given(solarNetClient.queueInstruction(eq(INSTRUCTION_TOPIC_STOP_REMOTE_SSH), eq(NODE_ID), any(),
        anyLong(), anyString())).willReturn(null).willReturn(instructionIds.incrementAndGet());
    assertThrows(AuthorizationException.class,
        () -> service.stopSession(sess.getId(), Instant.now().toEpochMilli(), "auth"),
        "Stop fails when instruction not queued");
    assertSame(sess, service.findOne(sess.getId()), "Session remains after failed stop");

    // WHEN
    service.stopSession(sess.getId(), Instant.now().toEpochMilli(), "auth");

    // THEN
    assertNull(service.findOne(sess.getId()), "Session deleted");
    then(solarNetClient).should(times(2)).queueInstruction(eq(INSTRUCTION_TOPIC_STOP_REMOTE_SSH),
        eq(NODE_ID), any(), anyLong(), anyString());
  }

  @Test
  public void attachTerminal() throws Exception {
    // GIVEN
    SshServer nodeShell = startNodeShellServer();
    SshSession sess = service.createNewSession(NODE_ID, Instant.now().toEpochMilli(), "auth");
    connectNode(sess.getId(), sess.getReverseSshPort(), nodeKey, nodeShell.getPort());
    assertEventually(() -> sess.getServerSession() != null, "Node session bound");
    PipedOutputStream terminalIn = new PipedOutputStream();
    ByteArrayOutputStream terminalOut = new ByteArrayOutputStream();

    // WHEN
    attachNodeShell(sess, NODE_SHELL_PASSWORD, terminalIn, terminalOut);
    terminalIn.write("ping\n".getBytes(UTF_8));
    terminalIn.flush();

    // THEN
    assertNotNull(sess.getClientSession(), "Terminal attached");
    assertEventually(() -> terminalOut.toString(UTF_8).contains("ping"), "Shell reached");

    // and WHEN
    terminalIn.write("exit\n".getBytes(UTF_8));
    terminalIn.flush();

    // THEN
    assertEventually(() -> sess.getClientSession() == null, "Terminal detached");
    assertEventually(() -> nodeShell.getActiveSessions().isEmpty(),
        "Terminal connection closed when shell exits");
    assertNotNull(service.findOne(sess.getId()), "Node session remains");
  }

  @Test
  public void attachTerminalReplacesExistingTerminal() throws Exception {
    // GIVEN
    SshServer nodeShell = startNodeShellServer();
    SshSession sess = service.createNewSession(NODE_ID, Instant.now().toEpochMilli(), "auth");
    connectNode(sess.getId(), sess.getReverseSshPort(), nodeKey, nodeShell.getPort());
    assertEventually(() -> sess.getServerSession() != null, "Node session bound");
    attachNodeShell(sess, NODE_SHELL_PASSWORD, new PipedOutputStream(),
        new ByteArrayOutputStream());
    final ClientSession first = sess.getClientSession();
    PipedOutputStream terminalIn = new PipedOutputStream();
    ByteArrayOutputStream terminalOut = new ByteArrayOutputStream();

    // WHEN
    attachNodeShell(sess, NODE_SHELL_PASSWORD, terminalIn, terminalOut);

    // THEN
    final ClientSession second = sess.getClientSession();
    assertNotNull(second, "Terminal attached");
    assertEventually(() -> !first.isOpen(), "Replaced terminal connection closed");
    assertEventually(() -> nodeShell.getActiveSessions().size() == 1,
        "Only the new terminal is connected");
    assertSame(second, sess.getClientSession(),
        "Closing the replaced terminal does not detach the new one");
    terminalIn.write("ping\n".getBytes(UTF_8));
    terminalIn.flush();
    assertEventually(() -> terminalOut.toString(UTF_8).contains("ping"), "New terminal works");
  }

  @Test
  public void attachTerminalBadPasswordReleasesResources() throws Exception {
    // GIVEN
    SshServer nodeShell = startNodeShellServer();
    SshSession sess = service.createNewSession(NODE_ID, Instant.now().toEpochMilli(), "auth");
    connectNode(sess.getId(), sess.getReverseSshPort(), nodeKey, nodeShell.getPort());
    assertEventually(() -> sess.getServerSession() != null, "Node session bound");
    assertThrows(IOException.class,
        () -> attachNodeShell(sess, "not the password", new PipedOutputStream(),
            new ByteArrayOutputStream()),
        "Bad password rejected");
    assertEventually(() -> nodeShell.getActiveSessions().isEmpty(), "Connection closed");
    final long clientCount = sshClientCount();

    // WHEN
    final int attempts = 10;
    for (int i = 0; i < attempts; i++) {
      assertThrows(IOException.class,
          () -> attachNodeShell(sess, "not the password", new PipedOutputStream(),
              new ByteArrayOutputStream()),
          "Bad password rejected");
    }

    // THEN
    assertNull(sess.getClientSession(), "Terminal not attached");
    assertEventually(() -> nodeShell.getActiveSessions().isEmpty(),
        "Failed terminal connections closed");
    assertEquals(clientCount, sshClientCount(), "Failed terminal connections do not leak clients");
  }

  @Test
  public void directSshThroughNode() throws Exception {
    // GIVEN
    ClientSession direct = connectDirect(client);

    // WHEN
    direct.auth().verify(TIMEOUT_SECS, SECONDS);

    // THEN
    assertEquals(1, nodeSessions.size(), "Node connected");
    final String sessionId = nodeSessions.get(0).getUsername();
    // the destination is ignored: all direct-tcpip channels go to the node's reverse port
    try (ChannelDirectTcpip channel = direct.createDirectTcpipChannel(
        new SshdSocketAddress("localhost", 0), new SshdSocketAddress("example.com", 80))) {
      channel.open().verify(TIMEOUT_SECS, SECONDS);
      BufferedReader in = new BufferedReader(
          new InputStreamReader(channel.getInvertedOut(), UTF_8));
      assertEquals("ping", echoLine(channel.getInvertedIn(), in, "ping"), "Reached node");
    }

    // and WHEN
    direct.close(false).await(TIMEOUT_SECS, SECONDS);

    // THEN
    assertNodeSessionEnded(sessionId);
  }

  @Test
  public void directSshBadPassword() throws Exception {
    // GIVEN
    ClientSession direct = client.connect(DIRECT_USERNAME, "127.0.0.1", directPort)
        .verify(TIMEOUT_SECS, SECONDS).getSession();
    direct.addPasswordIdentity("not the secret");

    // THEN
    assertThrows(IOException.class, () -> direct.auth().verify(TIMEOUT_SECS, SECONDS),
        "Bad password rejected");
    then(solarNetClient).should(never()).queueInstruction(any(), any(), any(), anyLong(),
        anyString());
    direct.close();
  }

  @Test
  public void directSshClientDisconnectsWhileWaitingForNode() throws Exception {
    // GIVEN
    nodeResponds = false;
    ClientSession direct = connectDirect(client);
    direct.auth();
    assertEventually(() -> sessionCount() == 1, "Session created for client");

    // WHEN
    direct.close(false).await(TIMEOUT_SECS, SECONDS);

    // THEN
    assertEventually(() -> sessionCount() == 0, "Session deleted");
    then(solarNetClient).should().queueInstruction(eq(INSTRUCTION_TOPIC_STOP_REMOTE_SSH),
        eq(NODE_ID), any(), anyLong(), anyString());
  }

  @Test
  public void directSshClientDisconnectsBeforeAuthenticationCompletes() throws Exception {
    // GIVEN
    // send each password request twice without waiting for a reply: the second fails because the
    // first is in progress, and the server then discards the result of the first, so the client
    // never authenticates even though the node connects
    SshClient pipeliningClient = SshClient.setUpDefaultClient();
    pipeliningClient.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);
    pipeliningClient.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
    pipeliningClient.setUserAuthFactories(List.of(new UserAuthPasswordFactory() {

      @Override
      public UserAuthPassword createUserAuth(ClientSession session) throws IOException {
        return new UserAuthPassword() {

          @Override
          protected IoWriteFuture sendPassword(Buffer buffer, ClientSession session,
              String oldPassword, String newPassword) throws Exception {
            super.sendPassword(buffer, session, oldPassword, newPassword);
            return super.sendPassword(buffer, session, oldPassword, newPassword);
          }
        };
      }
    }));
    pipeliningClient.start();
    try {
      ClientSession direct = connectDirect(pipeliningClient);
      direct.auth().await(TIMEOUT_SECS, SECONDS);
      assertEventually(() -> !nodeSessions.isEmpty() && nodeSessions.get(0).isAuthenticated(),
          "Node connected");
      final String sessionId = nodeSessions.get(0).getUsername();
      assertNotNull(service.findOne(sessionId), "Session exists while client connected");

      // WHEN
      direct.close(false).await(TIMEOUT_SECS, SECONDS);

      // THEN
      assertNodeSessionEnded(sessionId);
    } finally {
      pipeliningClient.stop();
    }
  }

}
