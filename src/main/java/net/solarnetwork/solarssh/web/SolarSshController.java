/* ==================================================================
 * SolarSshController.java - 16/06/2017 4:36:32 PM
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

import static net.solarnetwork.codec.JsonUtils.getJSONString;
import static net.solarnetwork.solarssh.Globals.AUDIT_LOG;
import static net.solarnetwork.solarssh.web.WebConstants.PRESIGN_AUTHORIZATION_HEADER;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.cache.Cache;

import org.apache.sshd.common.RuntimeSshException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import net.solarnetwork.solarssh.AuthorizationException;
import net.solarnetwork.solarssh.Globals;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.service.SolarSshService;
import net.solarnetwork.web.jakarta.domain.Response;
import net.solarnetwork.web.jakarta.security.WebConstants;

/**
 * Web controller for connection commands.
 * 
 * @author matt
 * @version 1.3
 */
@RestController
@RequestMapping("/api/v1/ssh")
public class SolarSshController {

  private final Logger log = LoggerFactory.getLogger(getClass());

  private final SolarSshService solarSshService;

  @Autowired(required = false)
  @Qualifier("brute-force-deny-list")
  private Cache<InetAddress, Byte> bruteForceDenyList;

  @Value("${ssh.bruteForce.maxTries:3}")
  private int bruteForceMaxTries = 3;

  @Autowired
  public SolarSshController(SolarSshService solarSshService) {
    super();
    this.solarSshService = solarSshService;
  }

  /**
   * Request an unused reverse SSH port.
   * 
   * @param nodeId
   *        the node ID to create the session for
   * @param request
   *        the request
   * @return the created session
   * @throws IOException
   *         if any communication error occurs
   */
  @RequestMapping(value = "/session/new", method = RequestMethod.GET)
  public Response<SshSession> createNewSession(@RequestParam("nodeId") Long nodeId,
      HttpServletRequest request) throws IOException {
    long authorizationDate = request.getDateHeader(WebConstants.HEADER_DATE);
    String preSignedAuthorization = request.getHeader(PRESIGN_AUTHORIZATION_HEADER);
    try {
      SshSession session = solarSshService.createNewSession(nodeId, authorizationDate,
          preSignedAuthorization);
      return Response.response(session);
    } catch (AuthorizationException e) {
      handleAuthFailureBruteForce(request, nodeId, preSignedAuthorization);
      throw e;
    }
  }

  /**
   * Issue a {@literal StartRemoteSsh} instruction and start the reverse SSH connection.
   * 
   * @param sessionId
   *        the SSH session ID
   * @param request
   *        the request
   * @return the updated session
   * @throws IOException
   *         if any communication error occurs
   */
  @RequestMapping(value = "/session/{sessionId}/start", method = RequestMethod.GET)
  public Response<SshSession> startSession(@PathVariable("sessionId") String sessionId,
      HttpServletRequest request) throws IOException {
    long authorizationDate = request.getDateHeader(WebConstants.HEADER_DATE);
    String preSignedAuthorization = request.getHeader(PRESIGN_AUTHORIZATION_HEADER);
    try {
      SshSession session = solarSshService.startSession(sessionId, authorizationDate,
          preSignedAuthorization);
      return Response.response(session);
    } catch (AuthorizationException e) {
      handleAuthFailureBruteForce(request, sessionId, preSignedAuthorization);
      throw e;
    }
  }

  /**
   * Issue a {@literal StopRemoteSsh} instruction and stop the reverse SSH connection.
   * 
   * @param sessionId
   *        the SSH session ID
   * @param request
   *        the request
   * @return the updated session
   * @throws IOException
   *         if any communication error occurs
   */
  @RequestMapping(value = "/session/{sessionId}/stop", method = RequestMethod.GET)
  public Response<SshSession> stopSession(@PathVariable("sessionId") String sessionId,
      HttpServletRequest request) throws IOException {
    long authorizationDate = request.getDateHeader(WebConstants.HEADER_DATE);
    String preSignedAuthorization = request.getHeader(PRESIGN_AUTHORIZATION_HEADER);
    SshSession session = solarSshService.stopSession(sessionId, authorizationDate,
        preSignedAuthorization);
    return Response.response(session);
  }

  /**
   * Handle an IOException.
   * 
   * @param e
   *        the exception
   * @return the response
   */
  @ExceptionHandler(IOException.class)
  public ResponseEntity<Response<Object>> ioException(IOException e) {
    return new ResponseEntity<Response<Object>>(
        new Response<Object>(Boolean.FALSE, "570", e.getMessage(), null), HttpStatus.BAD_GATEWAY);
  }

  /**
   * Handle an AuthorizationException.
   * 
   * @param e
   *        the exception
   * @return the response
   */
  @ExceptionHandler(AuthorizationException.class)
  public ResponseEntity<Response<Object>> authException(AuthorizationException e) {
    return new ResponseEntity<Response<Object>>(
        new Response<Object>(Boolean.FALSE, "571", e.getMessage(), null), HttpStatus.FORBIDDEN);
  }

  private static final Pattern SNWS_V2_KEY_PATTERN = Pattern.compile("Credential=([^,]+)(?:,|$)");

  private void handleAuthFailureBruteForce(HttpServletRequest request, Object sessionId,
      String preSignedAuthorization) {
    if (bruteForceDenyList == null) {
      return;
    }
    String remoteAddr = request.getRemoteAddr();
    String proxyRemoteAddr = request.getHeader("X-Forwarded-For");
    if (proxyRemoteAddr != null) {
      remoteAddr = proxyRemoteAddr;
    }
    try {
      InetAddress src = InetAddress.getByName(remoteAddr);
      if (!src.isLoopbackAddress()) {
        Byte count = bruteForceDenyList.get(src);
        if (count == null) {
          count = (byte) 1;
        } else if (count.byteValue() != (byte) 0xFF) {
          count = (byte) ((count.byteValue() & 0xFF) + 1);
        }
        log.info("{} authentication attempt [{}] failed: attempt {}", src, sessionId,
            Byte.toUnsignedInt(count));
        bruteForceDenyList.put(src, count);
        final int attempts = Byte.toUnsignedInt(count);
        if (attempts >= bruteForceMaxTries) {
          String username = null;
          Matcher m = SNWS_V2_KEY_PATTERN.matcher(preSignedAuthorization);
          if (m.find()) {
            username = m.group(1);
          }
          logBruteForceDeny(username, src, attempts, "block");
          throw new RuntimeSshException("Blocked.");
        }
      }
    } catch (UnknownHostException e) {
      // nothing we can do
    }
  }

  private void logBruteForceDeny(String username, InetAddress src, int count,
      String auditEventName) {
    log.info("{} authentication attempt [{}] blocked after {} attempts", src, username, count);
    Map<String, Object> auditProps = Globals.auditEventMap(username, auditEventName);
    auditProps.put("remoteAddress", src);
    auditProps.put("attempts", count);
    AUDIT_LOG.info(getJSONString(auditProps, "{}"));
  }

  /**
   * Get the brute force deny list.
   * 
   * @return the deny list
   */
  public Cache<InetAddress, Byte> getBruteForceDenyList() {
    return bruteForceDenyList;
  }

  /**
   * Set the brute force deny list.
   * 
   * @param bruteForceDenyList
   *        the deny list to set
   */
  public void setBruteForceDenyList(Cache<InetAddress, Byte> bruteForceDenyList) {
    this.bruteForceDenyList = bruteForceDenyList;
  }

  /**
   * Get the brute force max tries.
   * 
   * @return the max tries
   */
  public int getBruteForceMaxTries() {
    return bruteForceMaxTries;
  }

  /**
   * Set the brute force max tries.
   * 
   * @param bruteForceMaxTries
   *        the count to set
   */
  public void setBruteForceMaxTries(int bruteForceMaxTries) {
    this.bruteForceMaxTries = bruteForceMaxTries;
  }

}
