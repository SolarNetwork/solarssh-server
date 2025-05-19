/* ==================================================================
 * SolarSshPasswordAuthenticator.java - 11/08/2020 11:08:31 AM
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

import static java.util.Collections.singletonMap;
import static net.solarnetwork.solarssh.Globals.DEFAULT_SN_HOST;
import static net.solarnetwork.solarssh.service.SolarNetClient.INSTRUCTION_TOPIC_START_REMOTE_SSH;
import static net.solarnetwork.solarssh.service.SolarNetClient.INSTRUCTION_TOPIC_STOP_REMOTE_SSH;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import net.solarnetwork.security.Snws2AuthorizationBuilder;
import net.solarnetwork.solarssh.AuthorizationException;
import net.solarnetwork.solarssh.dao.ActorDao;
import net.solarnetwork.solarssh.domain.Actor;
import net.solarnetwork.solarssh.domain.DirectSshUsername;
import net.solarnetwork.solarssh.domain.SolarNodeInstructionState;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.service.SolarNetClient;
import net.solarnetwork.solarssh.service.SolarSshService;

/**
 * {@link PasswordAuthenticator} for direct SolarSSH connections.
 * 
 * @author matt
 * @version 1.1
 */
public class SolarSshPasswordAuthenticator implements PasswordAuthenticator {

  /**
   * The default value for the {@code maxNodeInstructionWaitSecs} property.
   */
  public static final int DEFAULT_MAX_NODE_INSTRUCTION_WAIT_SECS = 300;

  /**
   * The default value for the {@code instructionCompletedWaitMs} property.
   */
  public static final long DEFAULT_INSTRUCTION_COMPLETED_WAIT_MS = 1000L;

  /**
   * The default value for the {@code instructionIncompletedWaitMs} property.
   */
  public static final long DEFAULT_INSTRUCTION_INCOMPLETED_WAIT_MS = 1000L;

  private static final Logger log = LoggerFactory.getLogger(SolarSshPasswordAuthenticator.class);

  private final SolarSshService solarSshService;
  private final ActorDao actorDao;
  private String snHost = DEFAULT_SN_HOST;
  private int maxNodeInstructionWaitSecs = DEFAULT_MAX_NODE_INSTRUCTION_WAIT_SECS;
  private long instructionCompletedWaitMs = DEFAULT_INSTRUCTION_COMPLETED_WAIT_MS;
  private long instructionIncompleteWaitMs = DEFAULT_INSTRUCTION_INCOMPLETED_WAIT_MS;

  /**
   * Constructor.
   * 
   * @param solarSshService
   *        the SolarSSH service
   * @param actorDao
   *        the authentication DAO
   */
  public SolarSshPasswordAuthenticator(SolarSshService solarSshService, ActorDao actorDao) {
    super();
    this.solarSshService = solarSshService;
    this.actorDao = actorDao;
  }

  @Override
  public boolean authenticate(String username, String password, ServerSession session)
      throws PasswordChangeRequiredException, AsyncAuthException {
    final DirectSshUsername directUsername;
    try {
      directUsername = DirectSshUsername.valueOf(username);
    } catch (IllegalArgumentException e) {
      log.debug("Username [{}] is not a valid direct username.", username);
      return false;
    }
    final Long nodeId = directUsername.getNodeId();
    final String tokenId = directUsername.getTokenId();
    SshSession sshSession = null;
    Actor actor = actorDao.getAuthenticatedActor(nodeId, tokenId, password);
    if (actor != null) {
      // node + token checks out; create new node SSH session now
      Instant now = Instant.now();
      Snws2AuthorizationBuilder authBuilder = new Snws2AuthorizationBuilder(tokenId)
          .saveSigningKey(password).date(now).host(snHost)
          .path("/solaruser/api/v1/sec/instr/viewPending")
          .queryParams(singletonMap("nodeId", nodeId.toString()));
      Map<String, String> instructionParams = null;
      try {
        sshSession = solarSshService.createNewSession(nodeId, now.toEpochMilli(),
            authBuilder.build());
        sshSession.setDirectServerSession(session);
        sshSession.setTokenSecret(password);
        sshSession.setEstablished(true);

        instructionParams = SolarNetClient.createRemoteSshInstructionParams(sshSession);
        // CHECKSTYLE OFF: LineLength
        log.info(
            "Authenticated token {} for node {}; requesting node to connect to SolarSSH with parameters {}",
            tokenId, nodeId, instructionParams);
        // CHECKSTYLE ON: LineLength
        instructionParams.put("nodeId", nodeId.toString());
        instructionParams.put("topic", INSTRUCTION_TOPIC_START_REMOTE_SSH);
        now = Instant.now();
        authBuilder.reset().method(HttpMethod.POST.toString()).date(now).host(snHost)
            .path("/solaruser/api/v1/sec/instr/add")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .queryParams(instructionParams);
        sshSession = solarSshService.startSession(sshSession.getId(), now.toEpochMilli(),
            authBuilder.build());
        return waitForNodeInstructionToComplete(sshSession.getId(), nodeId, tokenId,
            INSTRUCTION_TOPIC_START_REMOTE_SSH, sshSession.getStartInstructionId(), authBuilder);
      } catch (AuthorizationException e) {
        log.info("Authorization failed creating new SshSession for {}", username);
      } catch (IOException e) {
        log.info("Communication error creating new SshSession: {}", e.toString());
        // if we started the node remote SSH, stop it now
        if (sshSession != null) {
          instructionParams.put("topic", INSTRUCTION_TOPIC_STOP_REMOTE_SSH);
          now = Instant.now();
          authBuilder.reset().method(HttpMethod.POST.toString()).date(now).host(snHost)
              .path("/solaruser/api/v1/sec/instr/add")
              .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
              .queryParams(instructionParams);
          try {
            solarSshService.stopSession(sshSession.getId(), now.toEpochMilli(),
                authBuilder.build());
          } catch (Exception e2) {
            // ignore
          }
          log.info("Issued {} instruction for token {} node {} with parameters {}",
              INSTRUCTION_TOPIC_STOP_REMOTE_SSH, tokenId, nodeId, instructionParams);
        }
        throw new RuntimeSshException("Communication error creating new SshSession", e);
      }
    }
    return false;
  }

  private boolean waitForNodeInstructionToComplete(String sessionId, Long nodeId, String tokenId,
      String topic, Long instructionId, Snws2AuthorizationBuilder authBuilder) throws IOException {
    final long expire = System.currentTimeMillis() + (1000L * this.maxNodeInstructionWaitSecs);
    while (System.currentTimeMillis() < expire) {
      Instant now = Instant.now();
      authBuilder.reset().date(now).host(snHost).path("/solaruser/api/v1/sec/instr/view")
          .queryParams(singletonMap("id", instructionId.toString()));
      SolarNodeInstructionState state = solarSshService.getInstructionState(instructionId,
          now.toEpochMilli(), authBuilder.build());
      if (state == SolarNodeInstructionState.Completed) {
        log.info("Token {} {} instruction {} completed", tokenId, topic, instructionId);
        while (System.currentTimeMillis() < expire) {
          SshSession sess = solarSshService.findOne(sessionId);
          if (sess == null) {
            break;
          }
          if (sess.getServerSession() != null) {
            // node has connected; good to go!
            return true;
          }
          // wait a few ticks for node SSH connection to actually be established
          try {
            Thread.sleep(instructionCompletedWaitMs);
          } catch (InterruptedException e) {
            break;
          }
        }
        throw new IOException("Timeout waiting " + this.maxNodeInstructionWaitSecs
            + "s for session " + sessionId + " node " + nodeId + " connection after instruction "
            + instructionId + " completed.");
      } else if (state == SolarNodeInstructionState.Declined) {
        log.info("Token {} {} instruction {} was declined.", tokenId, topic, instructionId);
        throw new RuntimeSshException("Session " + sessionId + " node " + nodeId + " instruction "
            + instructionId + " was declined.");
      }
      // wait a few ticks
      try {
        Thread.sleep(instructionIncompleteWaitMs);
      } catch (InterruptedException e) {
        break;
      }
    }
    throw new IOException("Timeout waiting " + this.maxNodeInstructionWaitSecs + "s for session "
        + sessionId + " node " + nodeId + " instruction {}" + instructionId + " to complete.");
  }

  /**
   * Get the configured SolarNetwork host.
   * 
   * @return the host; defaults to {@link net.solarnetwork.solarssh.Globals#DEFAULT_SN_HOST}
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
   * Set the maximum number of seconds to wait for a node instruction to complete.
   * 
   * @param maxNodeInstructionWaitSecs
   *        the maximum seconds; defaults to {@link #DEFAULT_MAX_NODE_INSTRUCTION_WAIT_SECS}
   */
  public void setMaxNodeInstructionWaitSecs(int maxNodeInstructionWaitSecs) {
    this.maxNodeInstructionWaitSecs = maxNodeInstructionWaitSecs;
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
