/* ==================================================================
 * SshSessionForwardFilter.java - 21/06/2017 11:46:13 AM
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

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.forward.RejectAllForwardingFilter;

import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * {@link ForwardingFilter} that allows only listening on the loopback host using the
 * {@link SshSession#getReverseSshPort()} configured with the connection.
 * 
 * <p>
 * The {@link SshSession#getReverseSshPort()} +1 port is also allowed.
 * </p>
 * 
 * @author matt
 * @version 1.0
 */
public class SshSessionForwardFilter extends RejectAllForwardingFilter {

  private final SshSessionDao sessionDao;

  public SshSessionForwardFilter(SshSessionDao sessionDao) {
    super();
    this.sessionDao = sessionDao;
  }

  @Override
  public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
    if (type == Type.Direct) {
      SshSession sess = sessionDao.findOne(session);
      return (sess != null && SshdSocketAddress.isLoopback(address.getHostName())
          && address.getPort() == sess.getReverseSshPort());
    }
    return checkAcceptance(type.getName(), session, address);
  }

  @Override
  public boolean canListen(SshdSocketAddress address, Session session) {
    String sessionId = session.getUsername();
    SshSession sess = sessionDao.findOne(sessionId);
    return (sess != null && SshdSocketAddress.isLoopback(address.getHostName())
        && (address.getPort() == sess.getReverseSshPort()
            || address.getPort() == sess.getReverseSshPort() + 1));
  }

}
