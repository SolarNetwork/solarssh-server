/* ==================================================================
 * WebMvcConfigCorsTests.java - 9/10/2026 10:00:00 AM
 *
 * Copyright 2026 SolarNetwork.net Dev Team
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

import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import net.solarnetwork.solarssh.config.JsonConfig;
import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.service.SolarSshService;
import net.solarnetwork.solarssh.web.SolarSshController;
import net.solarnetwork.solarssh.web.SolarSshHttpProxyController;

/**
 * Test cases for the CORS configuration in {@link WebMvcConfig}.
 *
 * @author matt
 * @version 1.0
 */
@SpringJUnitWebConfig(WebMvcConfigCorsTests.TestConfig.class)
public class WebMvcConfigCorsTests {

  private static final String ORIGIN = "https://evil.example.com";
  private static final String API_PATH = "/api/v1/ssh/session/new";
  private static final String PROXY_PATH = "/nodeproxy/00000000-0000-0000-0000-000000000000/";

  /**
   * Test context with the real controllers and mocked services.
   */
  @Configuration
  @EnableWebMvc
  @Import(WebMvcConfig.class)
  static class TestConfig {

    @Bean
    public SolarSshController solarSshController() {
      return new SolarSshController(mock(SolarSshService.class));
    }

    @Bean
    public SolarSshHttpProxyController solarSshHttpProxyController() {
      return new SolarSshHttpProxyController(mock(SshSessionDao.class));
    }

    @Bean(JsonConfig.CBOR_MAPPER)
    public ObjectMapper cborObjectMapper() {
      return new ObjectMapper(new CBORFactory());
    }

  }

  @Autowired
  private WebApplicationContext ctx;

  private MockMvc mvc;

  @BeforeEach
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(ctx).build();
  }

  @Test
  public void apiPreflight_anyOriginWithoutCredentials() throws Exception {
    mvc.perform(options(API_PATH).header(HttpHeaders.ORIGIN, ORIGIN)
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,
            "X-SN-Date,X-SN-PreSignedAuthorization"))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS))
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
            containsStringIgnoringCase("X-SN-PreSignedAuthorization")))
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
            containsStringIgnoringCase("GET")));
  }

  @Test
  public void apiPreflight_unsupportedMethod() throws Exception {
    mvc.perform(options(API_PATH).header(HttpHeaders.ORIGIN, ORIGIN)
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "DELETE"))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
  }

  @Test
  public void proxyPreflight_noCorsHeaders() throws Exception {
    mvc.perform(options(PROXY_PATH).header(HttpHeaders.ORIGIN, ORIGIN)
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
  }

  @Test
  public void proxyRequest_noCorsHeaders() throws Exception {
    mvc.perform(get(PROXY_PATH).header(HttpHeaders.ORIGIN, ORIGIN))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN))
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
  }

}
