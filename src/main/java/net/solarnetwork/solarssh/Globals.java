/* ========================================================================
 * Copyright 2020 SolarNetwork Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

package net.solarnetwork.solarssh;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.sshd.common.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.solarnetwork.solarssh.domain.SshSession;

/**
 * Some global references for the project.
 * 
 * @author matt
 * @version 1.0
 */
public final class Globals {

  /** A global "audit" logger for audit events to be logged to. */
  public static final Logger AUDIT_LOG = LoggerFactory.getLogger("SolarSshService.AUDIT");

  /**
   * The default value for the {@code snHost} property.
   */
  public static final String DEFAULT_SN_HOST = "data.solarnetwork.net";

  private Globals() {
    // can't construct me
  }

  /**
   * Create an audit event map.
   * 
   * @param session
   *        the session
   * @param sess
   *        the optional {@link SshSession} entity
   * @param eventName
   *        the event name
   * @return the map, never {@literal null}
   */
  public static Map<String, Object> auditEventMap(Session session, SshSession sess,
      String eventName) {
    String sessionId = (sess != null ? sess.getId() : session.getUsername());
    Map<String, Object> map;
    if (sess != null) {
      map = sess.auditEventMap(eventName);
    } else {
      map = new LinkedHashMap<>(8);
      map.put("sessionId", sessionId);
      map.put("event", eventName);
    }
    long now = System.currentTimeMillis();
    map.put("date", now);
    if (sess != null) {
      long secs = (long) Math.ceil((now - sess.getCreated()) / 1000.0);
      map.put("duration", secs);
    }
    return map;
  }

  /**
   * Create an audit event map.
   * 
   * @param sessionId
   *        the session ID or username
   * @param eventName
   *        the event name
   * @return the map, never {@literal null}
   */
  public static Map<String, Object> auditEventMap(String sessionId, String eventName) {
    Map<String, Object> map = new LinkedHashMap<>(8);
    map.put("sessionId", sessionId);
    map.put("event", eventName);
    long now = System.currentTimeMillis();
    map.put("date", now);
    return map;
  }

}
