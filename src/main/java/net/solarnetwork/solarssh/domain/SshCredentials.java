/* ==================================================================
 * SshCredentials.java - 23/06/2017 1:48:32 PM
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

import java.security.KeyPair;

/**
 * Credentials.
 * 
 * @author matt
 * @version 1.0
 */
public class SshCredentials {

  private final String username;
  private final String password;
  private final KeyPair keyPair;

  /**
   * Construct with a username and password.
   * 
   * @param username
   *        the username
   * @param password
   *        the password
   */
  public SshCredentials(String username, String password) {
    super();
    this.username = username;
    this.password = password;
    this.keyPair = null;
  }

  /**
   * Construct with a KeyPair.
   * 
   * @param keyPair
   *        the key pair
   */
  public SshCredentials(KeyPair keyPair) {
    super();
    this.username = null;
    this.password = null;
    this.keyPair = keyPair;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public KeyPair getKeyPair() {
    return keyPair;
  }

}
