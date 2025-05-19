/* ==================================================================
 * SolarNetClient.java - 17/06/2017 10:08:07 AM
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.solarnetwork.domain.datum.GeneralDatumMetadata;
import net.solarnetwork.solarssh.domain.SolarNetInstruction;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * API for SolarNet operations.
 * 
 * @author matt
 * @version 1.1
 */
public interface SolarNetClient {

  /**
   * View pending instructions.
   *
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal GET} request to the {@literal /solaruser/api/v1/sec/instr/viewPending} path
   * using the provided authorization date.
   * </p>
   * 
   * @param nodeId
   *        the SolarNode ID to instruct
   * @param authorizationDate
   *        the authorization date used in {@code authorization}
   * @param authorization
   *        the {@code Authorization} HTTP header value to use
   * @return the queued instruction ID
   * @throws IOException
   *         if any communication error occurs
   */
  List<SolarNetInstruction> pendingInstructions(Long nodeId, long authorizationDate,
      String authorization) throws IOException;

  /**
   * Get a specific instruction.
   * 
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal GET} request to the {@literal /api/v1/sec/instr/view?id=X} path using the
   * provided authorization date.
   * </p>
   * 
   * @param id
   *        the ID of the instruction to get
   * @return the instruction, or {@literal null} if the instruction does not exist
   */
  SolarNetInstruction getInstruction(Long id, long authorizationDate, String authorization)
      throws IOException;

  /**
   * Queue an instruction.
   * 
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal POST} request to the {@literal /solaruser/api/v1/sec/instr/add} path using
   * the provided authorization date, topic, node ID, and parameters. The parameters will be added
   * to the instruction in iteration order, which must match the order of the parameters as encoded
   * in {@code authorization}.
   * </p>
   * 
   * @param topic
   *        the command to queue
   * @param nodeId
   *        the SolarNode ID to instruct
   * @param parameters
   *        the instruction parameters
   * @param authorizationDate
   *        the authorization date used in {@code authorization}
   * @param authorization
   *        the {@code Authorization} HTTP header value to use
   * @return the queued instruction ID
   * @throws IOException
   *         if any communication error occurs
   */
  Long queueInstruction(String topic, Long nodeId, Map<String, ?> parameters,
      long authorizationDate, String authorization) throws IOException;

  /**
   * Get metadata for a node.
   *
   * <p>
   * The {@code authorization} should be a pre-computed SNWS2 authorization header, which must match
   * exactly a {@literal GET} request to the {@literal /solaruser/api/v1/sec/nodes/meta/:nodeId}
   * path using the provided authorization date and, node ID.
   * </p>
   * 
   * @param nodeId
   *        the ID of the node to get metadata for
   * @param authorizationDate
   *        the authorization date used in {@code authorization}
   * @param authorization
   *        the {@code Authorization} HTTP header value to use
   * @return the metadata (never {@literal null})
   * @throws IOException
   *         if any communication error occurs
   */
  GeneralDatumMetadata getNodeMetadata(Long nodeId, long authorizationDate, String authorization)
      throws IOException;

  /**
   * Add a SolarNetwork instruction parameter to a parameter map.
   * 
   * @param params
   *        the parameters to add the instruction parameters to
   * @param key
   *        the instruction parameter key
   * @param value
   *        the instruction parameter value
   */
  static void addInstructionParam(Map<String, String> params, String key, Object value) {
    int index = (params.size() / 2);
    params.put("parameters[" + index + "].name", key);
    params.put("parameters[" + index + "].value", value.toString());
  }

  /** The SolarNetwork instruction topic for a node to connect to SolarSSH. */
  String INSTRUCTION_TOPIC_START_REMOTE_SSH = "StartRemoteSsh";

  /** The SolarNetwork instruction topic for a node to disconnect from SolarSSH. */
  String INSTRUCTION_TOPIC_STOP_REMOTE_SSH = "StopRemoteSsh";

  String REVERSE_PORT_PARAM = "rport";
  String PORT_PARAM = "port";
  String USER_PARAM = "user";
  String HOST_PARAM = "host";

  /**
   * Create a SolarNetwork instruction parameters object for a given {@link SshSession}.
   * 
   * @param sess
   *        the session
   * @return the parameters
   */
  public static Map<String, String> createRemoteSshInstructionParams(SshSession sess) {
    Map<String, String> instructionParams = new LinkedHashMap<>(6);
    addInstructionParam(instructionParams, HOST_PARAM, sess.getSshHost());
    addInstructionParam(instructionParams, USER_PARAM, sess.getId());
    addInstructionParam(instructionParams, PORT_PARAM, sess.getSshPort());
    addInstructionParam(instructionParams, REVERSE_PORT_PARAM, sess.getReverseSshPort());
    return instructionParams;
  }

}
