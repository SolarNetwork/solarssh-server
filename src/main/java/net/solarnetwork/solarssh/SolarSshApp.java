/* ==================================================================
 * SolarSshApp.java - 11/08/2020 11:42:01 AM
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

package net.solarnetwork.solarssh;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import net.solarnetwork.solarssh.config.AppConfig;
import net.solarnetwork.solarssh.web.config.WebConfig;

/**
 * Main entry point for the SolarSSH server.
 * 
 * @author matt
 * @version 1.0
 */
@SpringBootApplication(scanBasePackageClasses = { SolarSshApp.class, AppConfig.class,
    WebConfig.class })
@EnableScheduling
public class SolarSshApp {

  /**
   * Command-line entry point to launching server.
   * 
   * @param args
   *        command line arguments
   */
  public static void main(String[] args) {
    SpringApplication.run(SolarSshApp.class, args);
  }

}
