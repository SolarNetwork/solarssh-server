/* ==================================================================
 * SolarSshHttpProxyController.java - 24/06/2017 5:17:37 PM
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

package net.solarnetwork.solarssh.web;

import java.io.IOException;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.solarnetwork.solarssh.AuthorizationException;
import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * Proxy controller for SolarNode over a reverse SSH tunnel.
 * 
 * @author matt
 * @version 1.1
 */
@Controller
public class SolarSshHttpProxyController {

  private final SshSessionDao sessionDao;

  // @formatter:off
  private final ConcurrentMap<String, SshSessionProxyServlet> sessionProxyMap 
      = new ConcurrentHashMap<>();
  // @formatter:on

  private static final Logger LOG = LoggerFactory.getLogger(SolarSshHttpProxyController.class);

  public SolarSshHttpProxyController(SshSessionDao sessionDao) {
    super();
    this.sessionDao = sessionDao;
  }

  /**
   * Proxy a HTTP request to the SolarNode associated with a session.
   * 
   * @param sessionId
   *        the {@link SshSession} ID to proxy
   * @param req
   *        the request
   * @param resp
   *        the response
   * @throws IOException
   *         if any communication error occurs
   * @throws ServletException
   *         if the {@link SshSessionProxyServlet} cannot be initialized
   */
  @RequestMapping(value = "/nodeproxy/{sessionId}/**", method = { RequestMethod.DELETE,
      RequestMethod.GET, RequestMethod.HEAD, RequestMethod.OPTIONS, RequestMethod.PATCH,
      RequestMethod.POST, RequestMethod.PUT, RequestMethod.TRACE })
  public void nodeProxy(@PathVariable("sessionId") String sessionId, HttpServletRequest req,
      HttpServletResponse resp) throws IOException, ServletException {
    SshSessionProxyServlet proxy = sessionProxyMap.computeIfAbsent(sessionId, k -> {
      SshSession session = sessionDao.findOne(sessionId);
      if (session == null || !session.isEstablished()) {
        throw new AuthorizationException("SshSession not available");
      }
      SshSessionProxyServlet s = new SshSessionProxyServlet(session,
          req.getContextPath() + "/nodeproxy/" + sessionId);
      try {
        s.init();
      } catch (ServletException e) {
        throw new RuntimeException(e);
      }
      return s;
    });
    LOG.debug("Context path: {}; requestURI: {}", req.getContextPath(), req.getRequestURI());
    proxy.service(req, resp);
  }

  /**
   * Call periodically to non-established sessions.
   */
  public void cleanupExpiredSessions() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Examining {} HTTP proxy sessions for expiration", sessionProxyMap.size());
    }
    for (Iterator<SshSessionProxyServlet> itr = sessionProxyMap.values().iterator(); itr
        .hasNext();) {
      SshSessionProxyServlet servlet = itr.next();
      SshSession sess = servlet.getSession();
      if (!sess.isEstablished()) {
        LOG.info("Expiring unestablished SshSessionProxyServlet {}: node {}, rport {}",
            sess.getId(), sess.getNodeId(), sess.getReverseSshPort());
        itr.remove();
        servlet.destroy();
      }
    }
  }

  /**
   * Handle an authorization error.
   * 
   * @param e
   *        the exception
   * @param resp
   *        the response
   */
  @ExceptionHandler(AuthorizationException.class)
  public void ioException(AuthorizationException e, HttpServletResponse resp) {
    try {
      resp.sendError(HttpStatus.FORBIDDEN.value(), e.getMessage());
    } catch (IOException e2) {
      // ignore
    }
  }

}
