/* ==================================================================
 * BruteForceDenyPasswordAuthenticator.java - 24/09/2020 6:43:36 am
 * 
 * Copyright 2020 SolarNetwork.net Dev Team
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

import java.net.InetAddress;

import javax.cache.Cache;

import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.session.ServerSession;

/**
 * {@link PasswordAuthenticator} that works with a brute force deny list.
 * 
 * @author matt
 * @version 1.0
 */
public class BruteForceDenyPasswordAuthenticator extends AbstractBruteForceAuthenticator
    implements PasswordAuthenticator {

  private final PasswordAuthenticator delegate;

  /**
   * Constructor.
   * 
   * @param delegate
   *        the delegate to use
   * @param denyList
   *        the deny list to use
   * @throws IllegalArgumentException
   *         if any argument is {@literal null}
   */
  public BruteForceDenyPasswordAuthenticator(PasswordAuthenticator delegate,
      Cache<InetAddress, Byte> denyList) {
    super(denyList);
    if (delegate == null) {
      throw new IllegalArgumentException("The delegate argument must not be null.");
    }
    this.delegate = delegate;
  }

  @Override
  public boolean authenticate(String username, String password, ServerSession session)
      throws PasswordChangeRequiredException, AsyncAuthException {
    boolean result = delegate.authenticate(username, password, session);
    if (!result) {
      handleAuthenticationFailure(username, session);
    }
    return result;
  }

}
