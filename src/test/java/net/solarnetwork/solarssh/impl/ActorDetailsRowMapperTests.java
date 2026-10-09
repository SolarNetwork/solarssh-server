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

import static org.assertj.core.api.BDDAssertions.and;
import static org.assertj.core.api.BDDAssertions.from;
import static org.mockito.BDDMockito.given;

import java.sql.Array;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import net.solarnetwork.domain.SecurityPolicy;
import net.solarnetwork.solarssh.domain.Actor;

/**
 * Test cases for the {@link ActorDetailsRowMapper} class.
 *
 * @author matt
 * @version 1.0
 */
@SuppressWarnings("static-access")
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
    // @formatter:off
    and.then(result)
        .as("Actor mapped")
        .isNotNull()
        .as("Token ID from constructor")
        .returns(TEST_TOKEN_ID, from(Actor::getTokenId))
        .as("User ID mapped")
        .returns(TEST_USER_ID, from(Actor::getUserId))
        .as("No policy mapped")
        .returns(null, from(Actor::getPolicy))
        ;
    and.then(result.getUserNodeIds())
        .as("User node IDs mapped in array order")
        .containsExactly(1L, 2L, 3L)
        ;
    and.then(result.getAllowedNodeIds())
        .as("All user node IDs allowed without policy")
        .containsExactly(1L, 2L, 3L)
        ;
    // @formatter:on
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
    // @formatter:off
    and.then(result.getPolicy())
        .as("Policy mapped")
        .isNotNull()
        .as("Policy node IDs mapped")
        .returns(Set.of(1L, 3L), from(SecurityPolicy::getNodeIds))
        .as("Policy source IDs mapped")
        .returns(Set.of("a", "b/*"), from(SecurityPolicy::getSourceIds))
        .as("Policy expiration mapped")
        .returns(notAfter, from(SecurityPolicy::getNotAfter))
        .as("Policy refresh allowed mapped")
        .returns(Boolean.TRUE, from(SecurityPolicy::getRefreshAllowed))
        ;
    and.then(result.getUserNodeIds())
        .as("User node IDs mapped")
        .containsExactlyInAnyOrder(1L, 2L, 3L)
        ;
    and.then(result.getAllowedNodeIds())
        .as("Allowed node IDs restricted by policy")
        .containsExactlyInAnyOrder(1L, 3L)
        ;
    // @formatter:on
  }

  @Test
  public void policy_nodeIdsNotOwned() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, "{\"nodeIds\":[1,99]}", new Long[] { 1L, 2L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    // @formatter:off
    and.then(result.getAllowedNodeIds())
        .as("Policy node IDs not owned by user are not allowed")
        .containsExactly(1L)
        ;
    // @formatter:on
  }

  @Test
  public void policy_emptyObject() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, "{}", new Long[] { 1L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    // @formatter:off
    and.then(result.getPolicy())
        .as("Empty policy mapped")
        .isNotNull()
        .as("No policy node IDs")
        .returns(null, from(SecurityPolicy::getNodeIds))
        ;
    and.then(result.getAllowedNodeIds())
        .as("All user node IDs allowed")
        .containsExactly(1L)
        ;
    // @formatter:on
  }

  @Test
  public void noNodeIdsArray() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, null);

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    // @formatter:off
    and.then(result.getUserNodeIds())
        .as("No user node IDs from SQL NULL array")
        .isEmpty()
        ;
    and.then(result.getAllowedNodeIds())
        .as("No allowed node IDs from SQL NULL array")
        .isEmpty()
        ;
    // @formatter:on
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
    // @formatter:off
    and.then(result.getUserNodeIds())
        .as("No user node IDs from null array data")
        .isEmpty()
        ;
    // @formatter:on
  }

  @Test
  public void emptyNodeIdsArray() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Long[0]);

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    // @formatter:off
    and.then(result.getUserNodeIds())
        .as("No user node IDs from empty array")
        .isEmpty()
        ;
    // @formatter:on
  }

  @Test
  public void nonLongNumberNodeIds() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Number[] { 1, 2L, (short) 3, 4.0 });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    // @formatter:off
    and.then(result.getUserNodeIds())
        .as("Number node IDs converted to Long")
        .containsExactly(1L, 2L, 3L, 4L)
        ;
    // @formatter:on
  }

  @Test
  public void nonNumberNodeIdsSkipped() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Object[] { 1L, "2", null, 3L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    // @formatter:off
    and.then(result.getUserNodeIds())
        .as("Non-number node IDs skipped")
        .containsExactly(1L, 3L)
        ;
    // @formatter:on
  }

  @Test
  public void duplicateNodeIds() throws Exception {
    // GIVEN
    givenRow(TEST_USER_ID, null, new Long[] { 2L, 1L, 2L });

    // WHEN
    Actor result = new ActorDetailsRowMapper(TEST_TOKEN_ID).mapRow(rs, 0);

    // THEN
    // @formatter:off
    and.then(result.getUserNodeIds())
        .as("Duplicate node IDs collapsed, first-seen order kept")
        .containsExactly(2L, 1L)
        ;
    // @formatter:on
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
    // @formatter:off
    and.then(result)
        .as("User ID mapped from custom column")
        .returns(TEST_USER_ID, from(Actor::getUserId))
        ;
    and.then(result.getPolicy())
        .as("Policy mapped from custom column")
        .isNotNull()
        .returns(Set.of(2L), from(SecurityPolicy::getNodeIds))
        ;
    and.then(result.getUserNodeIds())
        .as("Node IDs mapped from custom column")
        .containsExactly(1L, 2L)
        ;
    and.then(result.getAllowedNodeIds())
        .as("Allowed node IDs resolved")
        .containsExactly(2L)
        ;
    // @formatter:on
  }

}
