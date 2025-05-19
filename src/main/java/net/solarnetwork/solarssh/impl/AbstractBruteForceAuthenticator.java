/* ==================================================================
 * AbstractBruteForceAuthenticator.java - 24/09/2020 7:24:34 am
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

import static net.solarnetwork.codec.JsonUtils.getJSONString;
import static net.solarnetwork.solarssh.Globals.AUDIT_LOG;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;

import javax.cache.Cache;

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.solarnetwork.solarssh.Globals;

/**
 * Base class for brute force mitigation authenticators.
 * 
 * @author matt
 * @version 1.3
 */
public abstract class AbstractBruteForceAuthenticator {

  /** The audit event name when an IP address is tracked after an authentication failure. */
  public static final String AUDIT_EVENT_IP_TRACKING_FAILED_ATTEMPT = "IP-TRACK-FAIL";

  /** The audit event name when an IP address is blocked. */
  public static final String AUDIT_EVENT_IP_TRACKING_BLOCKED = "IP-TRACK-BLOCKED";

  protected final Logger log = LoggerFactory.getLogger(getClass());

  private final Cache<InetAddress, Byte> denyList;
  private int maxFails = 1;

  /**
   * Constructor.
   * 
   * @param denyList
   *        the deny list to use
   * @throws IllegalArgumentException
   *         if any argument is {@literal null}
   */
  public AbstractBruteForceAuthenticator(Cache<InetAddress, Byte> denyList) {
    super();
    if (denyList == null) {
      throw new IllegalArgumentException("The denyList argument must not be null.");
    }
    this.denyList = denyList;
  }

  /**
   * Handle an authentication failure.
   * 
   * @param username
   *        the username
   * @param session
   *        the session
   */
  protected void handleAuthenticationFailure(String username, ServerSession session) {
    if (session.getRemoteAddress() instanceof InetSocketAddress) {
      InetAddress src = ((InetSocketAddress) session.getRemoteAddress()).getAddress();
      if (!src.isLoopbackAddress()) {
        final Byte currCount = denyList.get(src);
        byte count = 0;
        if (currCount == null) {
          count = (byte) 1;
        } else if (currCount.byteValue() != (byte) 0xFF) {
          count = (byte) ((currCount.byteValue() & 0xFF) + 1);
        }
        final int attempts = Byte.toUnsignedInt(count);
        if (attempts >= maxFails) {
          session.close(false);
          log.info("{} authentication attempt [{}] blocked after {} attempts", src, username,
              attempts);
          auditBruteForceEvent(session, username, src, attempts, AUDIT_EVENT_IP_TRACKING_BLOCKED);
          throw new RuntimeSshException("Blocked.");
        } else {
          log.info("{} authentication attempt [{}] failed: attempt {}", src, username, attempts);
          if (currCount == null) {
            denyList.putIfAbsent(src, count);
          } else {
            denyList.replace(src, currCount, count);
          }
          auditBruteForceEvent(session, username, src, attempts,
              AUDIT_EVENT_IP_TRACKING_FAILED_ATTEMPT);
        }
      }
    }
  }

  private void auditBruteForceEvent(ServerSession session, String username, InetAddress src,
      int count, String auditEventName) {
    Map<String, Object> auditProps = Globals.auditEventMap(session, null, auditEventName);
    auditProps.put("remoteAddress", src);
    auditProps.put("attempts", count);
    auditProps.put("username", username);
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
