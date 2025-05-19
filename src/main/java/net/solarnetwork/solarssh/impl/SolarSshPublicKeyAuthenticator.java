/* ==================================================================
 * SolarSshPublicKeyAuthenticator.java - 21/06/2017 11:46:13 AM
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

package net.solarnetwork.solarssh.impl;

import java.security.PublicKey;

import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;

import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * Supports SSH public key authentication for active SSH sessions.
 * 
 * <p>
 * The presented {@code username} values must be existing session IDs.
 * </p>
 * 
 * @author matt
 * @version 1.0
 */
public class SolarSshPublicKeyAuthenticator implements PublickeyAuthenticator {

  private final SshSessionDao sessionDao;

  /**
   * Constructor.
   * 
   * @param sessionDao
   *        the DAO to access sessions with
   */
  public SolarSshPublicKeyAuthenticator(SshSessionDao sessionDao) {
    super();
    this.sessionDao = sessionDao;
  }

  @Override
  public boolean authenticate(String username, PublicKey key, ServerSession session) {
    SshSession sess = sessionDao.findOne(username);
    if (sess == null) {
      return false;
    }
    // TODO: validate
    return true;
  }

}
