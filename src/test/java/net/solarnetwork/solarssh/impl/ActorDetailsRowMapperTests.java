/* ==================================================================
 * ActorDetailsRowMapperTests.java - 9/10/2026 4:12:08 PM
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
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;

import java.sql.Array;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import net.solarnetwork.solarssh.domain.Actor;

/**
 * Test cases for the {@link ActorDetailsRowMapper} class.
 *
 * @author matt
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
public class ActorDetailsRowMapperTests {

  private static final String TEST_TOKEN_ID = "test.token";
  private static final Long TEST_USER_ID = 123L;

  @Mock
  private ResultSet rs;

  @Mock
  private Array nodeIdsArray;

  private void givenRow(Long userId, String policyJson, Object[] nodeIds) throws Exception {
    given(rs.getLong(ActorDetailsRowMapper.DEFAULT_USER_ID_COL)).willReturn(userId);
    given(rs.getString(ActorDetailsRowMapper.DEFAULT_TOKEN_TYPE_COL)).willReturn("ReadNodeData");
    given(rs.getString(ActorDetailsRowMapper.DEFAULT_POLICY_COL)).willReturn(policyJson);
    if (nodeIds != null) {
      given(rs.getArray(ActorDetailsRowMapper.DEFAULT_NODE_IDS_COL)).willReturn(nodeIdsArray);
      given(nodeIdsArray.getArray()).willReturn(nodeIds);
    }
  }

  @Test
  public void noPolicy() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Long[] { 1L, 2L, 3L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertNotNull(result, "Actor mapped");
    assertEquals(TEST_TOKEN_ID, result.getTokenId(), "Token ID from constructor");
    assertEquals(TEST_USER_ID, result.getUserId(), "User ID mapped");
    assertNull(result.getPolicy(), "No policy mapped");
    assertIterableEquals(List.of(1L, 2L, 3L), result.getUserNodeIds(),
        "User node IDs mapped in array order");
    assertIterableEquals(List.of(1L, 2L, 3L), result.getAllowedNodeIds(),
        "All user node IDs allowed without policy");
  }

  @Test
  public void policy() throws Exception {
    // GIVEN
    final Instant notAfter = Instant.parse("2030-01-01T00:00:00Z");
    givenRow(TEST_USER_ID, """
        {"nodeIds":[3,1],"sourceIds":["a","b/*"],"notAfter":%d,"refreshAllowed":true}
        """.formatted(notAfter.toEpochMilli()), new Long[] { 1L, 2L, 3L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertNotNull(result.getPolicy(), "Policy mapped");
    assertEquals(Set.of(1L, 3L), result.getPolicy().getNodeIds(), "Policy node IDs mapped");
    assertEquals(Set.of("a", "b/*"), result.getPolicy().getSourceIds(),
        "Policy source IDs mapped");
    assertEquals(notAfter, result.getPolicy().getNotAfter(), "Policy expiration mapped");
    assertEquals(Boolean.TRUE, result.getPolicy().getRefreshAllowed(),
        "Policy refresh allowed mapped");
    assertEquals(Set.of(1L, 2L, 3L), result.getUserNodeIds(), "User node IDs mapped");
    assertEquals(Set.of(1L, 3L), result.getAllowedNodeIds(),
        "Allowed node IDs restricted by policy");
  }

  @Test
  public void policy_nodeIdsNotOwned() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, "{\"nodeIds\":[1,99]}", new Long[] { 1L, 2L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertEquals(Set.of(1L), result.getAllowedNodeIds(),
        "Policy node IDs not owned by user are not allowed");
  }

  @Test
  public void policy_emptyObject() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, "{}", new Long[] { 1L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertNotNull(result.getPolicy(), "Empty policy mapped");
    assertNull(result.getPolicy().getNodeIds(), "No policy node IDs");
    assertEquals(Set.of(1L), result.getAllowedNodeIds(), "All user node IDs allowed");
  }

  @Test
  public void noNodeIdsArray() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, null);

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertTrue(result.getUserNodeIds().isEmpty(), "No user node IDs from SQL NULL array");
    assertTrue(result.getAllowedNodeIds().isEmpty(), "No allowed node IDs from SQL NULL array");
  }

  @Test
  public void nullArrayData() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, null);
    given(rs.getArray(ActorDetailsRowMapper.DEFAULT_NODE_IDS_COL)).willReturn(nodeIdsArray);
    given(nodeIdsArray.getArray()).willReturn(null);

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertTrue(result.getUserNodeIds().isEmpty(), "No user node IDs from null array data");
  }

  @Test
  public void emptyNodeIdsArray() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Long[0]);

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertTrue(result.getUserNodeIds().isEmpty(), "No user node IDs from empty array");
  }

  @Test
  public void nonLongNumberNodeIds() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Number[] { 1, 2L, (short) 3, 4.0 });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertIterableEquals(List.of(1L, 2L, 3L, 4L), result.getUserNodeIds(),
        "Number node IDs converted to Long");
  }

  @Test
  public void nonNumberNodeIdsSkipped() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Object[] { 1L, "2", null, 3L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertIterableEquals(List.of(1L, 3L), result.getUserNodeIds(),
        "Non-number node IDs skipped");
  }

  @Test
  public void duplicateNodeIds() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Long[] { 2L, 1L, 2L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    assertIterableEquals(List.of(2L, 1L), result.getUserNodeIds(),
        "Duplicate node IDs collapsed, first-seen order kept");
  }

  @Test
  public void customColumns() throws Exception {
    // GIVEN
    given(rs.getLong(5)).willReturn(TEST_USER_ID);
    given(rs.getString(6)).willReturn("User");
    given(rs.getString(7)).willReturn("{\"nodeIds\":[2]}");
    given(rs.getArray(8)).willReturn(nodeIdsArray);
    given(nodeIdsArray.getArray()).willReturn(new Long[] { 1L, 2L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID, 5, 6, 7, 8).mapRow(rs, 0);

    // THEN
    assertEquals(TEST_USER_ID, result.getUserId(), "User ID mapped from custom column");
    assertEquals(Set.of(2L), result.getPolicy().getNodeIds(),
        "Policy mapped from custom column");
    assertEquals(Set.of(1L, 2L), result.getUserNodeIds(),
        "Node IDs mapped from custom column");
    assertEquals(Set.of(2L), result.getAllowedNodeIds(), "Allowed node IDs resolved");
  }

}
