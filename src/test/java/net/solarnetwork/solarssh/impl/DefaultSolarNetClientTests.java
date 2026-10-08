/* ==================================================================
 * DefaultSolarNetClientTests.java - 8/10/2026 9:00:00 PM
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

package net.solarnetwork.solarssh.impl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.solarnetwork.solarssh.impl.DefaultSolarNetClient.RATE_LIMIT_RETRY_AFTER_HEADER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import net.solarnetwork.solarssh.RateLimitExceededException;
import net.solarnetwork.solarssh.domain.SolarNetInstruction;
import net.solarnetwork.solarssh.domain.SolarNodeInstructionState;

/**
 * Test cases for the {@link DefaultSolarNetClient} class.
 *
 * @author matt
 * @version 1.0
 */
public class DefaultSolarNetClientTests {

  private static final String AUTHORIZATION = "SNWS2 Credential=token,"
      + "SignedHeaders=host;x-sn-date,Signature=0123456789abcdef";
  private static final long RETRY_DELAY_MS = 200L;

  private HttpServer server;
  private DefaultSolarNetClient client;

  /** The number of initial requests to reject with a rate limit error. */
  private final AtomicInteger rateLimitCount = new AtomicInteger();
  private final List<String> requestBodies = new CopyOnWriteArrayList<>();

  @BeforeEach
  public void setup() throws IOException {
    server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext("/solaruser/api/v1/sec/instr/view",
        exchange -> respond(exchange, """
            {"success":true,"data":{"id":1,"nodeId":123,"topic":"StartRemoteSsh",
            "state":"Completed"}}"""));
    server.createContext("/solaruser/api/v1/sec/instr/add",
        exchange -> respond(exchange, """
            {"success":true,"data":{"id":2,"nodeId":123,"topic":"StartRemoteSsh",
            "state":"Queued"}}"""));
    server.start();

    client = new DefaultSolarNetClient();
    client.setApiBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
  }

  @AfterEach
  public void teardown() {
    server.stop(0);
  }

  private void respond(HttpExchange exchange, String json) throws IOException {
    requestBodies.add(new String(exchange.getRequestBody().readAllBytes(), UTF_8));
    if (rateLimitCount.getAndDecrement() > 0) {
      exchange.getResponseHeaders().set(RATE_LIMIT_RETRY_AFTER_HEADER,
          String.valueOf(System.currentTimeMillis() + RETRY_DELAY_MS));
      exchange.sendResponseHeaders(429, -1);
    } else {
      byte[] body = json.getBytes(UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, body.length);
      exchange.getResponseBody().write(body);
    }
    exchange.close();
  }

  @Test
  public void rateLimitedRequestRetried() throws Exception {
    // GIVEN
    rateLimitCount.set(1);

    // WHEN
    final long start = System.currentTimeMillis();
    SolarNetInstruction result = client.getInstruction(1L, start, AUTHORIZATION);

    // THEN
    assertEquals(SolarNodeInstructionState.Completed, result.getState(), "Instruction returned");
    assertEquals(2, requestBodies.size(), "Request retried once");
    assertTrue(System.currentTimeMillis() - start >= RETRY_DELAY_MS - 50,
        "Retried after the date given by the server");
  }

  @Test
  public void rateLimitedPostRetried() throws Exception {
    // GIVEN
    rateLimitCount.set(1);

    // WHEN
    Long result = client.queueInstruction("StartRemoteSsh", 123L, Map.of("foo", "bar"),
        System.currentTimeMillis(), AUTHORIZATION);

    // THEN
    assertEquals(2L, result, "Instruction ID returned");
    assertEquals(2, requestBodies.size(), "Request retried once");
    assertEquals(requestBodies.get(0), requestBodies.get(1), "Same data posted again");
  }

  @Test
  public void rateLimitedLongerThanMaxWait() throws Exception {
    // GIVEN
    rateLimitCount.set(Integer.MAX_VALUE);
    client.setRateLimitMaxWaitMs(RETRY_DELAY_MS + 100);

    // WHEN
    RateLimitExceededException e = assertThrows(RateLimitExceededException.class,
        () -> client.getInstruction(1L, System.currentTimeMillis(), AUTHORIZATION));

    // THEN
    assertTrue(e.getRetryAfter() > 0, "Retry date provided");
    assertEquals(2, requestBodies.size(), "Retried while within maximum wait");
  }

  @Test
  public void rateLimitedNoRetry() throws Exception {
    // GIVEN
    rateLimitCount.set(1);
    client.setRateLimitMaxWaitMs(0);

    // WHEN
    assertThrows(RateLimitExceededException.class,
        () -> client.getInstruction(1L, System.currentTimeMillis(), AUTHORIZATION));

    // THEN
    assertEquals(1, requestBodies.size(), "Not retried");
  }

}
