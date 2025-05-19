/* ==================================================================
 * ServiceConfig.java - 16/06/2017 7:34:47 PM
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

package net.solarnetwork.solarssh.config;

import java.net.InetAddress;
import java.net.URI;

import javax.cache.Cache;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import net.solarnetwork.solarssh.impl.DefaultSolarNetClient;
import net.solarnetwork.solarssh.impl.DefaultSolarSshService;
import net.solarnetwork.solarssh.impl.DefaultSolarSshdDirectServer;
import net.solarnetwork.solarssh.impl.DefaultSolarSshdServer;
import net.solarnetwork.solarssh.impl.JdbcActorDao;
import net.solarnetwork.solarssh.service.SolarNetClient;
import net.solarnetwork.solarssh.service.SolarSshService;

/**
 * Main service configuration.
 * 
 * @author matt
 * @version 1.0
 */
@Configuration
@EnableScheduling
public class ServiceConfig {

  @Value("${ssh.host:ssh.solarnetwork.net}")
  private String sshHost = "ssh.solarnetwork.net";

  @Value("${ssh.port:8022}")
  private int sshPort = 8022;

  @Value("${ssh.keyResource:classpath:sshd-server-key}")
  private Resource sshKeyResource = new ClassPathResource("/sshd-server-key");

  @Value("${ssh.keyPassword:changeit}")
  private String sshKeyPassword = null;

  @Value("${ssh.bruteForce.maxTries:3}")
  private int bruteForceMaxTries = 3;

  @Value("${ssh.reversePort.min:50000}")
  private int sshReversePortMin = 50000;

  @Value("${ssh.reversePort.max:65000}")
  private int sshReversePortMax = 65000;

  @Value("${ssh.sessionExpireSeconds:300}")
  private int sessionExpireSeconds = 300;

  @Value("${solarnet.auth.timeoutSeconds:300}")
  private int authTimeoutSecs;

  @Value("${solarnet.auth.instructionCompletedWaitMs:1000}")
  private long instructionCompletedWaitMs = 1000L;

  @Value("${solarnet.auth.instructionIncompleteWaitMs:1000}")
  private long instructionIncompleteWaitMs = 1000L;

  @Value("${solarnet.baseUrl:https://data.solarnetwork.net}")
  private String solarNetBaseUrl = "https://data.solarnetwork.net";

  @Value("${ssh.direct.port:9022}")
  private int sshDirectPort = 9022;

  @Autowired
  private JdbcOperations jdbcOps;

  @Autowired(required = false)
  @Qualifier("brute-force-deny-list")
  private Cache<InetAddress, Byte> bruteForceDenyList;

  /**
   * Initialize the {@link SolarSshService} service.
   * 
   * @return the service
   */
  @Bean(initMethod = "init")
  public DefaultSolarSshService solarSshService() {
    DefaultSolarSshService service = new DefaultSolarSshService(solarNetClient());
    service.setHost(sshHost);
    service.setPort(sshPort);
    service.setMinPort(sshReversePortMin);
    service.setMaxPort(sshReversePortMax);
    service.setSessionExpireSeconds(sessionExpireSeconds);
    return service;
  }

  @Scheduled(fixedDelayString = "${ssh.sessionExpireCleanupJobMs:60000}")
  public void cleanupExpiredSessions() {
    solarSshService().cleanupExpiredSessions();
  }

  /**
   * Initialize the SolarNetClient.
   * 
   * @return the client
   */
  @Bean(initMethod = "init")
  public SolarNetClient solarNetClient() {
    DefaultSolarNetClient client = new DefaultSolarNetClient();
    client.setApiBaseUrl(solarNetBaseUrl);
    return client;
  }

  /**
   * Initialize the SSHD server service.
   * 
   * @return the service.
   */
  @Bean(initMethod = "start", destroyMethod = "stop")
  public DefaultSolarSshdServer solarSshdService() {
    DefaultSolarSshdServer service = new DefaultSolarSshdServer(solarSshService());
    service.setPort(sshPort);
    service.setServerKeyResource(sshKeyResource);
    service.setServerKeyPassword(sshKeyPassword);
    service.setBruteForceDenyList(bruteForceDenyList);
    service.setBruteForceMaxTries(bruteForceMaxTries);
    return service;
  }

  /**
   * Initialize the SSHD server service.
   * 
   * @return the service.
   */
  @Bean(initMethod = "start", destroyMethod = "stop")
  public DefaultSolarSshdDirectServer solarSshdDirectService() {
    DefaultSolarSshdDirectServer service = new DefaultSolarSshdDirectServer(solarSshService(),
        actorDao());
    service.setPort(sshDirectPort);
    service.setServerKeyResource(sshKeyResource);
    service.setServerKeyPassword(sshKeyPassword);
    service.setSnHost(snHost());
    service.setAuthTimeoutSecs(authTimeoutSecs);
    service.setInstructionCompletedWaitMs(instructionCompletedWaitMs);
    service.setInstructionIncompleteWaitMs(instructionIncompleteWaitMs);
    service.setBruteForceDenyList(bruteForceDenyList);
    service.setBruteForceMaxTries(bruteForceMaxTries);
    return service;
  }

  private String snHost() {
    URI uri = URI.create(solarNetBaseUrl);
    String snHost = uri.getHost();
    if (uri.getPort() > 0) {
      snHost += ":" + uri.getPort();
    }
    return snHost;
  }

  /**
   * Get the actor DAO.
   * 
   * @return the actor DAO
   */
  @Bean
  public JdbcActorDao actorDao() {
    JdbcActorDao dao = new JdbcActorDao(jdbcOps);
    return dao;
  }

}
