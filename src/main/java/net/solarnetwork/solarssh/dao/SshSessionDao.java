/* ==================================================================
 * SshSessionDao.java - 21/06/2017 11:47:35 AM
 * 
 * Copyright 2017 SolarNetwork.net Dev Team
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

import org.apache.sshd.common.session.Session;

import net.solarnetwork.solarssh.domain.SshSession;

/**
 * DAO API for {@link SshSession} objects.
 * 
 * @author matt
 * @version 1.0
 */
public interface SshSessionDao {

  /**
   * Retrieves a {@code SshSession} by its id.
   * 
   * @param id
   *        must not be {@literal null}.
   * @return the entity with the given id or {@literal null} if none found
   * @throws IllegalArgumentException
   *         if {@code id} is {@literal null}
   */
  SshSession findOne(String id);

  /**
   * Retrieve a {@code SshSession} for a specific SSHD session.
   * 
   * @param session
   *        the SSHD session
   * @return the matching entity, or {@literal null} if none found
   * @throws IllegalArgumentException
   *         if {@code session} is {@literal null}
   */
  SshSession findOne(Session session);

  /**
   * Deletes a given {@code SshSession}.
   * 
   * @param entity
   *        the session to delete
   * @throws IllegalArgumentException
   *         in case the given entity is {@literal null}.
   */
  void delete(SshSession entity);

}
