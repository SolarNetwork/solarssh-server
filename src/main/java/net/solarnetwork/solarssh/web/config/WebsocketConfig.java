/* ==================================================================
 * WebsocketConfig.java - 22/06/2017 12:19:23 PM
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

package net.solarnetwork.solarssh.web.config;

import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.server.standard.ServerEndpointExporter;
import org.springframework.web.socket.server.standard.ServerEndpointRegistration;

import net.solarnetwork.solarssh.web.SolarSshEndpoint;
import net.solarnetwork.solarssh.web.WebConstants;

/**
 * Websocket configuration.
 * 
 * @author matt
 * @version 1.0
 */
@Configuration
public class WebsocketConfig {

  /**
   * Get the SSH endpoint registration.
   * 
   * @return registration for the SSH websocket endpoint
   */
  @Bean
  public ServerEndpointRegistration sshEndpoint() {
    return new ServerEndpointRegistration("/ssh", SolarSshEndpoint.class) {

      {
        setSubprotocols(Collections.singletonList(WebConstants.SOLARSSH_WEBSOCKET_PROTOCOL));
      }

      @Override
      public boolean checkOrigin(String originHeaderValue) {
        // allow any origin
        return true;
      }

    };
  }

  @Bean
  public ServerEndpointExporter endpointExporter() {
    return new ServerEndpointExporter();
  }

}
