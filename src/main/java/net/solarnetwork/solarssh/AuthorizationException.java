/* ==================================================================
 * AuthorizationException.java - 17/06/2017 2:52:46 PM
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

package net.solarnetwork.solarssh;

/**
 * Authorization related exception.
 * 
 * @author matt
 * @version 1.0
 */
public class AuthorizationException extends RuntimeException {

  private static final long serialVersionUID = 4223070380282447483L;

  /**
   * Constructor.
   */
  public AuthorizationException() {
    super();
  }

  /**
   * Constructor.
   * 
   * @param message
   *          the message
   */
  public AuthorizationException(String message) {
    super(message);
  }

  /**
   * Constructor.
   * 
   * @param cause
   *          the cause
   */
  public AuthorizationException(Throwable cause) {
    super(cause);
  }

  /**
   * Constructor.
   * 
   * @param message
   *          the message
   * @param cause
   *          the cause
   */
  public AuthorizationException(String message, Throwable cause) {
    super(message, cause);
  }

}
