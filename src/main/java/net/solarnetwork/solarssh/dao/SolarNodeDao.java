/* ==================================================================
 * SolarNodeDao.java - 9/10/2026 10:12:41 AM
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

package net.solarnetwork.solarssh.dao;

/**
 * DAO API for SolarNode details.
 *
 * @author matt
 * @version 1.0
 */
public interface SolarNodeDao {

  /**
   * The node metadata info key SolarNode publishes its SSH public key under.
   */
  String METADATA_SSH_PUBLIC_KEY = "ssh-public-key";

  /**
   * Get the SSH public key a node has published to its metadata.
   *
   * @param nodeId
   *        the node ID
   * @return the public key, in OpenSSH {@code authorized_keys} format, or {@literal null} if the
   *         node has not published one
   */
  String findSshPublicKey(Long nodeId);

}
