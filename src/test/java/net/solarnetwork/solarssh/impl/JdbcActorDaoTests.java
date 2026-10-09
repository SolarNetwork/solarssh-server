/* ==================================================================
 * JdbcActorDaoTests.java - 9/10/2026 4:31:42 PM
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

import static org.assertj.core.api.BDDAssertions.and;
import static org.assertj.core.api.BDDAssertions.from;
import static org.assertj.core.api.BDDAssertions.thenIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import javax.cache.Cache;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;

import net.solarnetwork.domain.SecurityPolicy;
import net.solarnetwork.solarssh.domain.Actor;
import net.solarnetwork.solarssh.domain.ActorDetails;

/**
 * Test cases for the {@link JdbcActorDao} class.
 *
 * <p>
 * Each test runs in a transaction that is rolled back afterwards.
 * </p>
 *
 * @author matt
 * @version 1.0
 */
@SuppressWarnings("static-access")
@JdbcTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
@ExtendWith(MockitoExtension.class)
public class JdbcActorDaoTests {

  private static final Long TEST_LOC_ID = -1L;
  private static final Long TEST_USER_ID = -1L;
  private static final Long TEST_NODE_ID = -1L;
  private static final Long TEST_NODE_ID_2 = -2L;
  private static final String TEST_TOKEN_ID = "test-token-00000001";
  private static final String TEST_TOKEN_SECRET = "test-secret";
  private static final String TEST_CACHE_KEY = "Token-" + TEST_TOKEN_ID;

  /**
   * Test configuration, so the test does not need the web application configuration.
   */
  @Configuration
  public static class TestConfig {
    // auto-configured JDBC beans only
  }

  @Autowired
  private JdbcOperations jdbcOps;

  @Mock
  private Cache<String, Actor> cache;

  @Captor
  private ArgumentCaptor<Actor> actorCaptor;

  private JdbcActorDao dao;

  @BeforeEach
  public void setup() {
    dao = new JdbcActorDao(jdbcOps);
  }

  private void insertUser(Long userId, boolean enabled) {
    jdbcOps.update("""
        INSERT INTO solaruser.user_user (id, disp_name, email, password, enabled)
        VALUES (?, 'Test User', ?, 'password', ?)
        """, userId, "test" + userId + "@localhost", enabled);
  }

  private void insertUserNode(Long userId, Long nodeId, boolean archived) {
    jdbcOps.update("""
        INSERT INTO solarnet.sn_loc (id, country, time_zone)
        VALUES (?, 'NZ', 'Pacific/Auckland')
        ON CONFLICT (id) DO NOTHING
        """, TEST_LOC_ID);
    jdbcOps.update("INSERT INTO solarnet.sn_node (node_id, loc_id) VALUES (?, ?)", nodeId,
        TEST_LOC_ID);
    jdbcOps.update("""
        INSERT INTO solaruser.user_node (node_id, user_id, archived)
        VALUES (?, ?, ?)
        """, nodeId, userId, archived);
  }

  private void insertToken(Long userId, String tokenId, String secret, String status,
      String policyJson) {
    jdbcOps.update("""
        INSERT INTO solaruser.user_auth_token
          (auth_token, user_id, auth_secret, status, token_type, jpolicy)
        VALUES (?, ?, ?, ?::solaruser.user_auth_token_status,
          'User'::solaruser.user_auth_token_type, ?::jsonb)
        """, tokenId, userId, secret, status, policyJson);
  }

  private void givenActiveUserWithNodes() {
    insertUser(TEST_USER_ID, true);
    insertUserNode(TEST_USER_ID, TEST_NODE_ID, false);
    insertUserNode(TEST_USER_ID, TEST_NODE_ID_2, false);
  }

  @Test
  public void authenticated() {
    // GIVEN
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("Actor returned for valid credentials")
        .isNotNull()
        .as("Token ID")
        .returns(TEST_TOKEN_ID, from(Actor::getTokenId))
        .as("Token owner user ID")
        .returns(TEST_USER_ID, from(Actor::getUserId))
        .as("No policy")
        .returns(null, from(Actor::getPolicy))
        ;
    and.then(result.getUserNodeIds())
        .as("All user nodes returned")
        .containsExactlyInAnyOrder(TEST_NODE_ID, TEST_NODE_ID_2)
        ;
    and.then(result.getAllowedNodeIds())
        .as("All user nodes allowed")
        .containsExactlyInAnyOrder(TEST_NODE_ID, TEST_NODE_ID_2)
        ;
    // @formatter:on
  }

  @Test
  public void authenticated_policy() {
    // GIVEN
    final Instant notAfter = Instant.now().plus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", """
        {"nodeIds":[%d],"notAfter":%d}
        """.formatted(TEST_NODE_ID, notAfter.toEpochMilli()));

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("Actor returned for valid credentials with policy")
        .isNotNull()
        ;
    and.then(result.getPolicy())
        .as("Policy mapped")
        .isNotNull()
        .as("Policy node IDs")
        .returns(Set.of(TEST_NODE_ID), from(SecurityPolicy::getNodeIds))
        .as("Policy expiration")
        .returns(notAfter, from(SecurityPolicy::getNotAfter))
        ;
    and.then(result.getAllowedNodeIds())
        .as("Allowed nodes restricted by policy")
        .containsExactly(TEST_NODE_ID)
        ;
    // @formatter:on
  }

  @Test
  public void authenticated_customSnHostAndPath() {
    // GIVEN
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);
    dao.setSnHost("example.com");
    dao.setSnPath("/foo");

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("Actor returned when signing with custom host and path")
        .isNotNull()
        ;
    // @formatter:on
  }

  @Test
  public void wrongSecret() {
    // GIVEN
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, "not-the-secret");

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for wrong secret")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void unknownToken() {
    // GIVEN
    givenActiveUserWithNodes();

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for unknown token")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void disabledToken() {
    // GIVEN
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Disabled", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for disabled token")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void disabledUser() {
    // GIVEN
    insertUser(TEST_USER_ID, false);
    insertUserNode(TEST_USER_ID, TEST_NODE_ID, false);
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for disabled user")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void expiredPolicy() {
    // GIVEN
    final Instant notAfter = Instant.now().minus(1, ChronoUnit.HOURS);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active",
        "{\"notAfter\":%d}".formatted(notAfter.toEpochMilli()));

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for expired token policy")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void expiredPolicy_notVerifiedByAuthenticateCall() {
    // GIVEN
    final Instant notAfter = Instant.now().minus(1, ChronoUnit.HOURS);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active",
        "{\"notAfter\":%d}".formatted(notAfter.toEpochMilli()));

    // authenticate call that ignores the policy expiration date
    dao.setAuthenticateCall("""
        SELECT user_id, token_type, jpolicy
        FROM solaruser.user_auth_token
        WHERE auth_token = ?
          AND ?::timestamptz IS NOT NULL
          AND ?::text IS NOT NULL
          AND ?::text IS NOT NULL
          AND ?::text IS NOT NULL
        """);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for expired token policy returned by authenticate call")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void nodeNotOwned() {
    // GIVEN
    final Long otherUserId = -2L;
    final Long otherNodeId = -3L;
    givenActiveUserWithNodes();
    insertUser(otherUserId, true);
    insertUserNode(otherUserId, otherNodeId, false);
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(otherNodeId, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for node owned by another user")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void nodeNotInPolicy() {
    // GIVEN
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active",
        "{\"nodeIds\":[%d]}".formatted(TEST_NODE_ID));

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID_2, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for node not allowed by token policy")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void archivedNode() {
    // GIVEN
    insertUser(TEST_USER_ID, true);
    insertUserNode(TEST_USER_ID, TEST_NODE_ID, false);
    insertUserNode(TEST_USER_ID, TEST_NODE_ID_2, true);
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID_2, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    // @formatter:off
    and.then(result)
        .as("No actor for archived node")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void cache_miss() {
    // GIVEN
    dao.setActorCache(cache);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    then(cache).should().put(eq(TEST_CACHE_KEY), actorCaptor.capture());

    // @formatter:off
    and.then(result)
        .as("Actor returned")
        .isNotNull()
        ;
    and.then(actorCaptor.getValue())
        .as("Returned actor cached")
        .isSameAs(result)
        ;
    // @formatter:on
  }

  @Test
  public void cache_hit() {
    // GIVEN
    dao.setActorCache(cache);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // node ID not owned in DB, to prove the cached actor is used
    final Long cachedNodeId = -99L;
    final Actor cached = new ActorDetails(TEST_TOKEN_ID, TEST_USER_ID, null, Set.of(cachedNodeId));
    given(cache.get(TEST_CACHE_KEY)).willReturn(cached);

    // WHEN
    Actor result = dao.getAuthenticatedActor(cachedNodeId, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    then(cache).should(never()).put(anyString(), any());

    // @formatter:off
    and.then(result)
        .as("Cached actor returned")
        .isSameAs(cached)
        ;
    // @formatter:on
  }

  @Test
  public void cache_hit_wrongSecret() {
    // GIVEN
    dao.setActorCache(cache);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, "not-the-secret");

    // THEN
    then(cache).shouldHaveNoInteractions();

    // @formatter:off
    and.then(result)
        .as("Credentials verified before the actor cache is consulted")
        .isNull()
        ;
    // @formatter:on
  }

  @Test
  public void setters_rejectNull() {
    // @formatter:off
    thenIllegalArgumentException()
        .as("Null authenticate call rejected")
        .isThrownBy(() -> dao.setAuthenticateCall(null))
        ;
    thenIllegalArgumentException()
        .as("Null authorize call rejected")
        .isThrownBy(() -> dao.setAuthorizeCall(null))
        ;
    thenIllegalArgumentException()
        .as("Null host rejected")
        .isThrownBy(() -> dao.setSnHost(null))
        ;
    thenIllegalArgumentException()
        .as("Null path rejected")
        .isThrownBy(() -> dao.setSnPath(null))
        ;
    // @formatter:on
  }

}
