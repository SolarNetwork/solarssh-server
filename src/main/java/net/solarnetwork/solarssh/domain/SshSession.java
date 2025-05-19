/* ==================================================================
 * SshSession.java - 16/06/2017 5:21:48 PM
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

package net.solarnetwork.solarssh.domain;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.session.Session;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * A SSH session model object.
 * 
 * @author matt
 * @version 1.0
 */
@JsonPropertyOrder({ "sessionId", "created", "nodeId", "host", "port", "reversePort",
    "startInstructionId", "stopInstructionId", "lastUsed" })
public class SshSession {

  private final long created;
  private final String id;
  private final Long nodeId;
  private final String sshHost;
  private final int sshPort;
  private final int reverseSshPort;
  private final int reverseHttpPort;

  private boolean established;
  private Long startInstructionId;
  private Long stopInstructionId;
  private ClientSession clientSession;
  private Session serverSession;
  private Session directServerSession;
  private String tokenSecret;

  /**
   * Constructor.
   * 
   * @param created
   *        the creation date
   * @param id
   *        a globally unique ID to use for the session
   * @param nodeId
   *        the node ID to connect with
   * @param sshHost
   *        the SSH host for the node to connect to
   * @param sshPort
   *        the SSH port for the node to connect to
   * @param reverseSshPort
   *        a reverse SSH port to use
   * @param reverseHttpPort
   *        a reverse HTTP port to use
   */
  public SshSession(long created, String id, Long nodeId, String sshHost, int sshPort,
      int reverseSshPort, int reverseHttpPort) {
    super();
    this.created = created;
    this.id = id;
    this.nodeId = nodeId;
    this.sshHost = sshHost;
    this.sshPort = sshPort;
    this.reverseSshPort = reverseSshPort;
    this.reverseHttpPort = reverseHttpPort;
  }

  public boolean isEstablished() {
    return established;
  }

  public void setEstablished(boolean established) {
    this.established = established;
  }

  public long getCreated() {
    return created;
  }

  @JsonProperty("sessionId")
  public String getId() {
    return id;
  }

  @JsonProperty("reversePort")
  public int getReverseSshPort() {
    return reverseSshPort;
  }

  public Long getNodeId() {
    return nodeId;
  }

  @JsonProperty("host")
  public String getSshHost() {
    return sshHost;
  }

  @JsonProperty("port")
  public int getSshPort() {
    return sshPort;
  }

  @JsonIgnore
  public int getReverseHttpPort() {
    return reverseHttpPort;
  }

  @Override
  public String toString() {
    return "SshSession{id=" + id + ", nodeId=" + nodeId + ", reverseSshPort=" + reverseSshPort
        + "}";
  }

  public Long getStartInstructionId() {
    return startInstructionId;
  }

  public void setStartInstructionId(Long startInstructionId) {
    this.startInstructionId = startInstructionId;
  }

  public Long getStopInstructionId() {
    return stopInstructionId;
  }

  public void setStopInstructionId(Long stopInstructionId) {
    this.stopInstructionId = stopInstructionId;
  }

  @JsonIgnore
  public ClientSession getClientSession() {
    return clientSession;
  }

  @JsonIgnore
  public void setClientSession(ClientSession clientSession) {
    this.clientSession = clientSession;
  }

  @JsonIgnore
  public Session getServerSession() {
    return serverSession;
  }

  @JsonIgnore
  public void setServerSession(Session serverSession) {
    this.serverSession = serverSession;
  }

  @JsonIgnore
  public Session getDirectServerSession() {
    return directServerSession;
  }

  @JsonIgnore
  public void setDirectServerSession(Session serverSession) {
    this.directServerSession = serverSession;
  }

  @JsonIgnore
  public String getTokenSecret() {
    return tokenSecret;
  }

  @JsonIgnore
  public void setTokenSecret(String tokenSecret) {
    this.tokenSecret = tokenSecret;
  }

  /**
   * Get a Map of standard audit event properties.
   * 
   * @param eventName
   *        the audit event name
   * @return the properties
   */
  public Map<String, Object> auditEventMap(String eventName) {
    Map<String, Object> map = new LinkedHashMap<>(8);
    map.put("nodeId", nodeId);
    map.put("sessionId", id);
    map.put("event", eventName);
    return map;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((id == null) ? 0 : id.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    SshSession other = (SshSession) obj;
    if (id == null) {
      if (other.id != null) {
        return false;
      }
    } else if (!id.equals(other.id)) {
      return false;
    }
    return true;
  }

}
