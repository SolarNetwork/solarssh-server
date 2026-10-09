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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import javax.cache.Cache;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;

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
@JdbcTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
public class JdbcActorDaoTests {

  private static final Long TEST_LOC_ID = -1L;
  private static final Long TEST_USER_ID = -1L;
  private static final Long TEST_NODE_ID = -1L;
  private static final Long TEST_NODE_ID_2 = -2L;
  private static final String TEST_TOKEN_ID = "test-token-00000001";
  private static final String TEST_TOKEN_SECRET = "test-secret";

  /**
   * Test configuration, so the test does not need the web application configuration.
   */
  @Configuration
  public static class TestConfig {
    // auto-configured JDBC beans only
  }

  @Autowired
  private JdbcOperations jdbcOps;

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
    assertNotNull(result, "Actor returned for valid credentials");
    assertEquals(TEST_TOKEN_ID, result.getTokenId(), "Token ID");
    assertEquals(TEST_USER_ID, result.getUserId(), "Token owner user ID");
    assertNull(result.getPolicy(), "No policy");
    assertEquals(Set.of(TEST_NODE_ID, TEST_NODE_ID_2), result.getUserNodeIds(),
        "All user nodes returned");
    assertEquals(Set.of(TEST_NODE_ID, TEST_NODE_ID_2), result.getAllowedNodeIds(),
        "All user nodes allowed");
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
    assertNotNull(result, "Actor returned for valid credentials with policy");
    assertNotNull(result.getPolicy(), "Policy mapped");
    assertEquals(Set.of(TEST_NODE_ID), result.getPolicy().getNodeIds(), "Policy node IDs");
    assertEquals(notAfter, result.getPolicy().getNotAfter(), "Policy expiration");
    assertEquals(Set.of(TEST_NODE_ID), result.getAllowedNodeIds(),
        "Allowed nodes restricted by policy");
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
    assertNotNull(result, "Actor returned when signing with custom host and path");
  }

  @Test
  public void wrongSecret() {
    // GIVEN
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, "not-the-secret");

    // THEN
    assertNull(result, "No actor for wrong secret");
  }

  @Test
  public void unknownToken() {
    // GIVEN
    givenActiveUserWithNodes();

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    assertNull(result, "No actor for unknown token");
  }

  @Test
  public void disabledToken() {
    // GIVEN
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Disabled", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    assertNull(result, "No actor for disabled token");
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
    assertNull(result, "No actor for disabled user");
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
    assertNull(result, "No actor for expired token policy");
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
    assertNull(result, "No actor for expired token policy returned by authenticate call");
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
    assertNull(result, "No actor for node owned by another user");
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
    assertNull(result, "No actor for node not allowed by token policy");
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
    assertNull(result, "No actor for archived node");
  }

  @Test
  public void cache_miss() {
    // GIVEN
    @SuppressWarnings("unchecked")
    Cache<String, Actor> cache = mock(Cache.class);
    dao.setActorCache(cache);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    assertNotNull(result, "Actor returned");
    verify(cache).put("Token-" + TEST_TOKEN_ID, result);
  }

  @Test
  public void cache_hit() {
    // GIVEN
    @SuppressWarnings("unchecked")
    Cache<String, Actor> cache = mock(Cache.class);
    dao.setActorCache(cache);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // node ID not owned in DB, to prove the cached actor is used
    final Long cachedNodeId = -99L;
    final Actor cached = new ActorDetails(TEST_TOKEN_ID, TEST_USER_ID, null, Set.of(cachedNodeId));
    given(cache.get("Token-" + TEST_TOKEN_ID)).willReturn(cached);

    // WHEN
    Actor result = dao.getAuthenticatedActor(cachedNodeId, TEST_TOKEN_ID, TEST_TOKEN_SECRET);

    // THEN
    assertSame(cached, result, "Cached actor returned");
    verify(cache, never()).put(anyString(), any());
  }

  @Test
  public void cache_hit_wrongSecret() {
    // GIVEN
    @SuppressWarnings("unchecked")
    Cache<String, Actor> cache = mock(Cache.class);
    dao.setActorCache(cache);
    givenActiveUserWithNodes();
    insertToken(TEST_USER_ID, TEST_TOKEN_ID, TEST_TOKEN_SECRET, "Active", null);

    // WHEN
    Actor result = dao.getAuthenticatedActor(TEST_NODE_ID, TEST_TOKEN_ID, "not-the-secret");

    // THEN
    assertNull(result, "Credentials verified before the actor cache is consulted");
    verify(cache, never()).get(anyString());
  }

  @Test
  public void setters_rejectNull() {
    assertThrows(IllegalArgumentException.class, () -> dao.setAuthenticateCall(null),
        "Null authenticate call rejected");
    assertThrows(IllegalArgumentException.class, () -> dao.setAuthorizeCall(null),
        "Null authorize call rejected");
    assertThrows(IllegalArgumentException.class, () -> dao.setSnHost(null),
        "Null host rejected");
    assertThrows(IllegalArgumentException.class, () -> dao.setSnPath(null),
        "Null path rejected");
  }

}
