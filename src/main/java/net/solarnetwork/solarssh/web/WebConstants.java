/* ==================================================================
 * WebConstants.java - 17/06/2017 9:28:46 PM
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

/**
 * Web related constants.
 * 
 * @author matt
 * @version 1.0
 */
public final class WebConstants {

  /**
   * A HTTP header for a SNWS2 {@code Authorization} header value to pass through to SolarNetwork.
   */
  public static final String PRESIGN_AUTHORIZATION_HEADER = "X-SN-PreSignedAuthorization";

  /**
   * A websocket sub-protocol for establishing a connection to a remote shell terminal.
   */
  public static final String SOLARSSH_WEBSOCKET_PROTOCOL = "solarssh";

  private WebConstants() {
    // do not construct
  }

}
