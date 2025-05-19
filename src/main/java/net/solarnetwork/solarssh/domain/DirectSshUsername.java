/* ==================================================================
 * DirectSshUsername.java - 12/08/2020 10:06:52 AM
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

package net.solarnetwork.solarssh.domain;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A direct SSH username.
 * 
 * @author matt
 * @version 1.0
 */
public class DirectSshUsername {

  /**
   * A pattern to match the components of a direct username.
   */
  public static final Pattern DIRECT_USERNAME_PAT = Pattern.compile("^([0-9]+):(.*)");

  private final Long nodeId;
  private final String tokenId;

  /**
   * Get a direct username instance.
   * 
   * @param username
   *        the raw username value, e.g. {@literal 123:FOO}
   * @return the instance
   * @throws IllegalArgumentException
   *         if {@code username} is not a valid direct username
   */
  public static DirectSshUsername valueOf(String username) {
    Matcher m = DIRECT_USERNAME_PAT.matcher(username);
    if (!m.matches()) {
      throw new IllegalArgumentException("Not a valid direct username.");
    }
    return new DirectSshUsername(Long.valueOf(m.group(1)), m.group(2));
  }

  /**
   * Constructor.
   * 
   * @param nodeId
   *        the node ID
   * @param tokenId
   *        the token ID
   */
  public DirectSshUsername(Long nodeId, String tokenId) {
    super();
    this.nodeId = nodeId;
    this.tokenId = tokenId;
  }

  /**
   * Get the node ID.
   * 
   * @return the node ID
   */
  public Long getNodeId() {
    return nodeId;
  }

  /**
   * Get the token ID.
   * 
   * @return the token ID
   */
  public String getTokenId() {
    return tokenId;
  }

}
