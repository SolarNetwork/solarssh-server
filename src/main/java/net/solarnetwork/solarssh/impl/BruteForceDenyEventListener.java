/* ==================================================================
 * BruteForceDenyEventListener.java - 23/09/2020 10:45:27 am
 * 
 * Copyright 2020 SolarNetwork Foundation
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

import static net.solarnetwork.codec.JsonUtils.getJSONString;
import static net.solarnetwork.solarssh.Globals.AUDIT_LOG;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Map;

import javax.cache.Cache;

import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.solarnetwork.solarssh.Globals;

/**
 * {@link IoServiceEventListener} implementation for a dynamic "deny" firewall based on remote IP
 * addresses that fail to authenticate.
 * 
 * @author matt
 * @version 1.1
 */
public class BruteForceDenyEventListener implements IoServiceEventListener {

  private static final Logger log = LoggerFactory.getLogger(BruteForceDenyEventListener.class);

  private final Cache<InetAddress, Byte> denyList;
  private int maxFails = 1;

  /**
   * Constructor.
   * 
   * @param denyList
   *        the cache of blocked IP addresses
   * @throws IllegalArgumentException
   *         if any argument is {@literal null}
   */
  public BruteForceDenyEventListener(Cache<InetAddress, Byte> denyList) {
    super();
    if (denyList == null) {
      throw new IllegalArgumentException("The denyList argument must not be null.");
    }
    this.denyList = denyList;
  }

  @Override
  public void connectionAccepted(IoAcceptor acceptor, SocketAddress local, SocketAddress remote,
      SocketAddress service) throws IOException {
    if (remote instanceof InetSocketAddress) {
      InetAddress src = ((InetSocketAddress) remote).getAddress();
      if (denyList.containsKey(src)) {
        Byte count = denyList.get(src);
        if (count != null) {
          final int attempts = Byte.toUnsignedInt(count);
          if (attempts >= maxFails) {
            logBruteForceDeny(src, attempts, "blocked");
            throw new IOException("Blocked.");
          }
        }
      }
    }
  }

  private void logBruteForceDeny(InetAddress src, int count, String auditEventName) {
    log.info("{} connection blocked via brute force filter", src);
    Map<String, Object> auditProps = Globals.auditEventMap(src.toString(), auditEventName);
    auditProps.put("attempts", count);
    AUDIT_LOG.info(getJSONString(auditProps, "{}"));
  }

  /**
   * Get the max fails count.
   * 
   * @return the max fails before closing connection; defaults to {@literal 1}
   */
  public int getMaxFails() {
    return maxFails;
  }

  /**
   * Set the max fails count.
   * 
   * @param maxFails
   *        the count to set
   */
  public void setMaxFails(int maxFails) {
    this.maxFails = maxFails;
  }

}
