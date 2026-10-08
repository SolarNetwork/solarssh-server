/* ==================================================================
 * JdbcSolarNodeDao.java - 9/10/2026 10:18:03 AM
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

import static net.solarnetwork.util.ObjectUtils.requireNonNullArgument;

import java.util.List;

import org.springframework.jdbc.core.JdbcOperations;

import net.solarnetwork.solarssh.dao.SolarNodeDao;

/**
 * JDBC implementation of {@link SolarNodeDao}.
 *
 * @author matt
 * @version 1.0
 */
public class JdbcSolarNodeDao implements SolarNodeDao {

  // CHECKSTYLE OFF: LineLength

  /**
   * The default value for the {@code sshPublicKeyQuery} property.
   */
  public static final String DEFAULT_SSH_PUBLIC_KEY_QUERY = "SELECT solarnet.get_node_public_ssh_key(?)";

  // CHECKSTYLE ON: LineLength

  private final JdbcOperations jdbcOps;
  private String sshPublicKeyQuery = DEFAULT_SSH_PUBLIC_KEY_QUERY;

  /**
   * Constructor.
   *
   * @param jdbcOps
   *        the JDBC ops to use
   */
  public JdbcSolarNodeDao(JdbcOperations jdbcOps) {
    super();
    this.jdbcOps = jdbcOps;
  }

  @Override
  public String findSshPublicKey(Long nodeId) {
    List<String> results = jdbcOps.queryForList(sshPublicKeyQuery, String.class, nodeId);
    return (results.isEmpty() ? null : results.get(0));
  }

  /**
   * Get the SSH public key JDBC query.
   *
   * @return the JDBC query; defaults to {@link #DEFAULT_SSH_PUBLIC_KEY_QUERY}
   */
  public String getSshPublicKeyQuery() {
    return sshPublicKeyQuery;
  }

  /**
   * Set the SSH public key JDBC query.
   *
   * <p>
   * This JDBC statement is used to find the SSH public key a node has published. It is expected to
   * take the following parameters:
   * </p>
   *
   * <ol>
   * <li><b>node_id</b> ({@code Long}) - the SolarNode ID</li>
   * </ol>
   *
   * <p>
   * A result set with a single {@code String} column holding the public key in OpenSSH
   * {@code authorized_keys} format is expected. An empty result set, or a {@literal null} value,
   * means the node has not published a key.
   * </p>
   *
   * @param jdbcQuery
   *        the JDBC query
   * @throws IllegalArgumentException
   *         if {@code jdbcQuery} is {@literal null}
   */
  public void setSshPublicKeyQuery(String jdbcQuery) {
    this.sshPublicKeyQuery = requireNonNullArgument(jdbcQuery, "jdbcQuery");
  }

}
