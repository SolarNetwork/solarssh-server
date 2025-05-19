/* ==================================================================
 * WebMvcConfig.java - 17/06/2017 8:31:48 AM
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

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.cbor.MappingJackson2CborHttpMessageConverter;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.fasterxml.jackson.databind.ObjectMapper;

import net.solarnetwork.central.web.PingController;
import net.solarnetwork.service.PingTest;
import net.solarnetwork.solarssh.config.JsonConfig;
import net.solarnetwork.solarssh.web.SolarSshHttpProxyController;

/**
 * WebMVC configuration.
 * 
 * @author matt
 * @version 1.2
 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

  @Autowired
  private SolarSshHttpProxyController httpProxyController;

  @Autowired
  @Qualifier(JsonConfig.CBOR_MAPPER)
  private ObjectMapper cborObjectMapper;

  @Scheduled(fixedDelayString = "${ssh.sessionProxyExpireCleanupJobMs:60000}")
  public void cleanupExpiredSessions() {
    httpProxyController.cleanupExpiredSessions();
  }

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    // @formatter:off
    registry.addMapping("/**")
        .allowCredentials(true)
        .allowedOriginPatterns(CorsConfiguration.ALL)
        .maxAge(TimeUnit.HOURS.toSeconds(24))
        .allowedMethods("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
        .allowedHeaders(
            "Authorization",
            "Content-MD5",
            "Content-Type",
            "Digest",
            "X-SN-Date",
            "X-SN-PresignedAuthorization")
        ;
    // @formatter:on
  }

  @Override
  public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
    // update CBOR with our standard ObjectMapper
    for (HttpMessageConverter<?> c : converters) {
      if (c instanceof MappingJackson2CborHttpMessageConverter cbor) {
        cbor.setObjectMapper(cborObjectMapper);
      }
    }
  }

  @Controller
  @RequestMapping("/ping")
  static class SolarInPingController extends PingController {

    public SolarInPingController(List<PingTest> tests) {
      super(tests);
    }

  }

}
