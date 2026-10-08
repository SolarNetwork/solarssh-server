/* ==================================================================
 * JdbcSolarNodeDaoTests.java - 9/10/2026 11:02:17 AM
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

import static net.solarnetwork.solarssh.dao.SolarNodeDao.METADATA_SSH_PUBLIC_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;

import net.solarnetwork.codec.JsonUtils;
import net.solarnetwork.domain.datum.GeneralDatumMetadata;

/**
 * Test cases for the {@link JdbcSolarNodeDao} class.
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
public class JdbcSolarNodeDaoTests {

  private static final Long TEST_LOC_ID = -1L;
  private static final Long TEST_NODE_ID = -1L;

  // CHECKSTYLE OFF: LineLength
  private static final String TEST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGLHJSJhxPBx+N3NfIIffOTD2vLKvkqHd5JLHXfDZJRy solar@solarnode";
  // CHECKSTYLE ON: LineLength

  /**
   * Test configuration, so the test does not need the web application configuration.
   */
  @Configuration
  public static class TestConfig {
    // auto-configured JDBC beans only
  }

  @Autowired
  private JdbcOperations jdbcOps;

  private JdbcSolarNodeDao dao;

  @BeforeEach
  public void setup() {
    dao = new JdbcSolarNodeDao(jdbcOps);
  }

  private void insertNode(Long nodeId) {
    jdbcOps.update("""
        INSERT INTO solarnet.sn_loc (id, country, time_zone)
        VALUES (?, 'NZ', 'Pacific/Auckland')
        ON CONFLICT (id) DO NOTHING
        """, TEST_LOC_ID);
    jdbcOps.update("INSERT INTO solarnet.sn_node (node_id, loc_id) VALUES (?, ?)", nodeId,
        TEST_LOC_ID);
  }

  private void insertNodeMetadata(Long nodeId, GeneralDatumMetadata meta) {
    jdbcOps.update("""
        INSERT INTO solarnet.sn_node_meta (node_id, created, updated, jdata)
        VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?::jsonb)
        """, nodeId, JsonUtils.getJSONString(meta, null));
  }

  @Test
  public void findSshPublicKey() {
    // GIVEN
    insertNode(TEST_NODE_ID);
    GeneralDatumMetadata meta = new GeneralDatumMetadata();
    meta.putInfoValue("foo", "bar");
    meta.putInfoValue(METADATA_SSH_PUBLIC_KEY, TEST_KEY);
    meta.putInfoValue("prop", METADATA_SSH_PUBLIC_KEY, "not this one");
    insertNodeMetadata(TEST_NODE_ID, meta);

    // WHEN
    String result = dao.findSshPublicKey(TEST_NODE_ID);

    // THEN
    assertEquals(TEST_KEY, result, "Published key returned");
  }

  @Test
  public void findSshPublicKey_otherNode() {
    // GIVEN
    final Long otherNodeId = -2L;
    insertNode(TEST_NODE_ID);
    insertNode(otherNodeId);
    GeneralDatumMetadata meta = new GeneralDatumMetadata();
    meta.putInfoValue(METADATA_SSH_PUBLIC_KEY, TEST_KEY);
    insertNodeMetadata(otherNodeId, meta);

    // WHEN
    String result = dao.findSshPublicKey(TEST_NODE_ID);

    // THEN
    assertNull(result, "Key published by another node not returned");
  }

  @Test
  public void findSshPublicKey_noKey() {
    // GIVEN
    insertNode(TEST_NODE_ID);
    GeneralDatumMetadata meta = new GeneralDatumMetadata();
    meta.putInfoValue("foo", "bar");
    insertNodeMetadata(TEST_NODE_ID, meta);

    // WHEN
    String result = dao.findSshPublicKey(TEST_NODE_ID);

    // THEN
    assertNull(result, "No key returned when node metadata has no key");
  }

  @Test
  public void findSshPublicKey_noMetadata() {
    // GIVEN
    insertNode(TEST_NODE_ID);

    // WHEN
    String result = dao.findSshPublicKey(TEST_NODE_ID);

    // THEN
    assertNull(result, "No key returned when node has no metadata");
  }

  @Test
  public void findSshPublicKey_noNode() {
    // WHEN
    String result = dao.findSshPublicKey(TEST_NODE_ID);

    // THEN
    assertNull(result, "No key returned when node does not exist");
  }

}
