/* ==================================================================
 * SolarSshPasswordAuthenticatorTests.java - 8/10/2026 7:15:00 PM
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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.util.UUID;

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.server.session.ServerSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import net.solarnetwork.solarssh.dao.ActorDao;
import net.solarnetwork.solarssh.domain.Actor;
import net.solarnetwork.solarssh.domain.SolarNodeInstructionState;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.service.SolarSshService;

/**
 * Test cases for the {@link SolarSshPasswordAuthenticator} class.
 * 
 * @author matt
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
public class SolarSshPasswordAuthenticatorTests {

  private static final Long NODE_ID = 123L;
  private static final String TOKEN_ID = "token";
  private static final String USERNAME = NODE_ID + ":" + TOKEN_ID;
  private static final String PASSWORD = "secret";
  private static final Long INSTRUCTION_ID = 321L;

  /** Long enough that a test only finishes in time if it stops waiting early. */
  private static final int MAX_WAIT_SECS = 60;

  @Mock
  private SolarSshService solarSshService;

  @Mock
  private ActorDao actorDao;

  @Mock
  private Actor actor;

  @Mock
  private ServerSession session;

  private SshSession sshSession;
  private SolarSshPasswordAuthenticator auth;

  @BeforeEach
  public void setup() throws Exception {
    auth = new SolarSshPasswordAuthenticator(solarSshService, actorDao);
    auth.setMaxNodeInstructionWaitSecs(MAX_WAIT_SECS);
    auth.setInstructionIncompleteWaitMs(10);
    auth.setInstructionCompletedWaitMs(10);

    sshSession = new SshSession(System.currentTimeMillis(), UUID.randomUUID().toString(), NODE_ID,
        "localhost", 8022, 50000, 50001);
    sshSession.setStartInstructionId(INSTRUCTION_ID);

    given(actorDao.getAuthenticatedActor(NODE_ID, TOKEN_ID, PASSWORD)).willReturn(actor);
    given(solarSshService.createNewSession(eq(NODE_ID), anyLong(), anyString()))
        .willReturn(sshSession);
    given(solarSshService.startSession(eq(sshSession.getId()), anyLong(), anyString()))
        .willReturn(sshSession);
  }

  @Test
  public void nodeConnects() throws Exception {
    // GIVEN
    given(session.isOpen()).willReturn(true);
    given(solarSshService.getInstructionState(eq(INSTRUCTION_ID), anyLong(), anyString()))
        .willReturn(SolarNodeInstructionState.Completed);
    sshSession.setServerSession(mock(Session.class));
    given(solarSshService.findOne(sshSession.getId())).willReturn(sshSession);

    // WHEN
    boolean result = auth.authenticate(USERNAME, PASSWORD, session);

    // THEN
    assertTrue(result, "Authenticated once node connected");
  }

  @Test
  public void clientDisconnectsWhileInstructionIncomplete() throws Exception {
    // GIVEN
    given(session.isOpen()).willReturn(true, false);
    given(solarSshService.getInstructionState(eq(INSTRUCTION_ID), anyLong(), anyString()))
        .willReturn(SolarNodeInstructionState.Queued);

    // WHEN
    assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
      assertThrows(RuntimeSshException.class,
          () -> auth.authenticate(USERNAME, PASSWORD, session),
          "Disconnect ends the attempt with an exception, not a bad-password failure");
    }, "Stopped waiting once the client disconnected");

    // THEN
    then(solarSshService).should().getInstructionState(eq(INSTRUCTION_ID), anyLong(),
        anyString());
    then(solarSshService).should().stopSession(eq(sshSession.getId()), anyLong(), anyString());
  }

  @Test
  public void clientDisconnectsWhileWaitingForNode() throws Exception {
    // GIVEN
    given(session.isOpen()).willReturn(true, true, false);
    given(solarSshService.getInstructionState(eq(INSTRUCTION_ID), anyLong(), anyString()))
        .willReturn(SolarNodeInstructionState.Completed);
    given(solarSshService.findOne(sshSession.getId())).willReturn(sshSession);

    // WHEN
    assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
      assertThrows(RuntimeSshException.class,
          () -> auth.authenticate(USERNAME, PASSWORD, session),
          "Disconnect ends the attempt with an exception, not a bad-password failure");
    }, "Stopped waiting once the client disconnected");

    // THEN
    then(solarSshService).should().findOne(sshSession.getId());
    then(solarSshService).should().stopSession(eq(sshSession.getId()), anyLong(), anyString());
  }

}
