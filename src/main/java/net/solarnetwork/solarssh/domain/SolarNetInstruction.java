/* ==================================================================
 * SolarNetInstruction.java - 17/06/2017 9:36:20 PM
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

import static java.util.stream.Collectors.toMap;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * An instruction on SolarNetwork.
 * 
 * @author matt
 * @version 1.0
 */
public class SolarNetInstruction {

  private Long id;
  private String topic;
  private Long nodeId;
  private Date instructionDate;
  private SolarNodeInstructionState state;
  private List<SolarNetInstructionParameter> parameters;

  /**
   * Get the parameters as a single-valued map.
   * 
   * <p>
   * The parameter names become the keys in the returned map.
   * </p>
   * 
   * @return the parameters as a map
   */
  @JsonIgnore
  public Map<String, String> getParameterMap() {
    if (parameters == null || parameters.isEmpty()) {
      return Collections.emptyMap();
    }
    return parameters.stream().collect(toMap(p -> p.getName(), p -> p.getValue()));
  }

  /**
   * Get the first available parameter value for a given name.
   * 
   * @param name
   *        the parameter name
   * @return the value, or {@literal null} if not available
   */
  public String parameterValue(String name) {
    if (parameters == null) {
      return null;
    }
    for (SolarNetInstructionParameter p : parameters) {
      if (name.equals(p.getName())) {
        return p.getValue();
      }
    }
    return null;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public Long getNodeId() {
    return nodeId;
  }

  public void setNodeId(Long nodeId) {
    this.nodeId = nodeId;
  }

  public String getTopic() {
    return topic;
  }

  public void setTopic(String topic) {
    this.topic = topic;
  }

  public Date getInstructionDate() {
    return instructionDate;
  }

  public void setInstructionDate(Date instructionDate) {
    this.instructionDate = instructionDate;
  }

  public SolarNodeInstructionState getState() {
    return state;
  }

  public void setState(SolarNodeInstructionState state) {
    this.state = state;
  }

  public List<SolarNetInstructionParameter> getParameters() {
    return parameters;
  }

  public void setParameters(List<SolarNetInstructionParameter> parameters) {
    this.parameters = parameters;
  }

}
