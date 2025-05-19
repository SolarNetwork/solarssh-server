/* ==================================================================
 * SolarSshService.java - 16/06/2017 5:10:34 PM
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

package net.solarnetwork.solarssh.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SolarNodeInstructionState;
import net.solarnetwork.solarssh.domain.SshCredentials;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.domain.SshTerminalSettings;

/**
 * API for the SolarSSH service.
 * 
 * @author matt
 * @version 1.0
 */
public interface SolarSshService extends SshSessionDao {

  /**
   * Get a new session with an unused reverse SSH port.
   * 
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal GET} request to the {@literal /solaruser/api/v1/sec/instr/viewPending} path
   * using the provided authorization date.
   * </p>
   * 
   * <p>
   * The validity of this session is for only a short amount of time, if it is not subsequently
   * connected to a SSH pipe.
   * </p>
   * 
   * @param nodeId
   *        the SolarNode ID to instruct
   * @param authorizationDate
   *        the authorization date used in {@code authorization}
   * @param authorization
   *        the {@code Authorization} HTTP header value to use
   * @return a new session instance
   * @throws IOException
   *         for any communication error occurs
   */
  SshSession createNewSession(Long nodeId, long authorizationDate, String authorization)
      throws IOException;

  /**
   * Start a session.
   * 
   * <p>
   * Starting a session means enqueuing a <code>StartRemoteSsh</code> instruction for the session's
   * node ID and SSH host, user, port, and reverse port settings.
   * </p>
   *
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal POST} request to the {@literal /solaruser/api/v1/sec/instr/add} path using
   * the provided authorization date, <code>StartRemoteSsh</code> topic, node ID from the session,
   * and the following instruction parameters, in this order:
   * </p>
   * 
   * <ol>
   * <li><code>host</code> - the <code>host</code> property from the session</li>
   * <li><code>user</code> - the <code>sessionId</code> property from the session</li>
   * <li><code>port</code> - the <code>port</code> property from the session</li>
   * <li><code>rport</code> - the <code>reverseSshPort</code> property from the session</li>
   * </ol>
   *
   * @param sessionId
   *        the ID of the session to start
   * @param authorizationDate
   *        the authorization date used in {@code authorization}
   * @param authorization
   *        the {@code Authorization} HTTP header value to use
   * @return the session instance, which will be populated with the <code>startInstructionId</code>
   *         returned from enqueuing the <code>StartRemoteSsh</code> instruction
   * @throws IOException
   *         for any communication error occurs
   */
  SshSession startSession(String sessionId, long authorizationDate, String authorization)
      throws IOException;

  /**
   * Get the state of an instruction.
   * 
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal GET} request to the {@literal /api/v1/sec/instr/view?id=X} path using the
   * provided authorization date.
   * </p>
   * 
   * @param id
   *        the ID of the instruction to get
   * @param authorizationDate
   *        the authorization date used in {@code authorization}
   * @param authorization
   *        the {@code Authorization} HTTP header value to use
   * @return the state
   * @throws IOException
   *         for any communication error occurs
   */
  SolarNodeInstructionState getInstructionState(Long id, long authorizationDate,
      String authorization) throws IOException;

  /**
   * Attach a SSH shell terminal to input and output streams.
   * 
   * <p>
   * This method will make a request to SolarNetwork for the metadata associated with the session's
   * node ID.
   * </p>
   * 
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal GET} request to the {@literal /solaruser/api/v1/sec/nodes/meta/:nodeId}
   * path using the provided authorization date and, node ID.
   * </p>
   * 
   * @param sessionId
   *        the ID of the session to attach
   * @param authorizationDate
   *        the authorization date used in {@code authorization}
   * @param authorization
   *        the {@code Authorization} HTTP header value to use
   * @param nodeCredentials
   *        credentials to use when connecting to the node via SSH
   * @param settings
   *        terminal settings to use for the remote shell
   * @param in
   *        an input stream to receive {@literal UTF-8} encoded text on and use as {@literal STDIN}
   *        for the remote shell
   * @param out
   *        an output stream to send {@literal UTF-8} encoded text to that is received from
   *        {@literal STDOUT} and {@code STDERR} on the remote shell
   * @return the session instance
   * @throws IOException
   *         for any communication error occurs
   */
  SshSession attachTerminal(String sessionId, long authorizationDate, String authorization,
      SshCredentials nodeCredentials, SshTerminalSettings settings, InputStream in,
      OutputStream out) throws IOException;

  /**
   * Stop a session.
   * 
   * <p>
   * This will close any attached remote terminal shell (started via {@link #attachTerminal}) and
   * post a <code>StopRemoteSsh</code> instruction to SolarNetwork for the session's node ID.
   * </p>
   * 
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal POST} request to the {@literal /solaruser/api/v1/sec/instr/add} path using
   * the provided authorization date, <code>StopRemoteSsh</code> topic, node ID from the session,
   * and the following instruction parameters, in this order:
   * </p>
   * 
   * <ol>
   * <li><code>host</code> - the <code>host</code> property from the session</li>
   * <li><code>user</code> - the <code>sessionId</code> property from the session</li>
   * <li><code>port</code> - the <code>port</code> property from the session</li>
   * <li><code>rport</code> - the <code>reverseSshPort</code> property from the session</li>
   * </ol>
   *
   * @param sessionId
   *        the ID of the session to stop
   * @param authorizationDate
   *        the authorization date used in {@code authorization}
   * @param authorization
   *        the {@code Authorization} HTTP header value to use
   * @return the session instance
   * @throws IOException
   *         for any communication error occurs
   */
  SshSession stopSession(String sessionId, long authorizationDate, String authorization)
      throws IOException;
}
