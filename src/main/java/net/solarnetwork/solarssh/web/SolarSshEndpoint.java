/* ==================================================================
 * SolarSshEndpoint.java - Jun 11, 2017 3:19:12 PM
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

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import jakarta.websocket.CloseReason;
import jakarta.websocket.CloseReason.CloseCodes;
import jakarta.websocket.Endpoint;
import jakarta.websocket.EndpointConfig;
import jakarta.websocket.MessageHandler;
import jakarta.websocket.Session;
import net.solarnetwork.codec.JsonUtils;
import net.solarnetwork.solarssh.AuthorizationException;
import net.solarnetwork.solarssh.domain.SshCredentials;
import net.solarnetwork.solarssh.domain.SshSession;
import net.solarnetwork.solarssh.domain.SshTerminalSettings;
import net.solarnetwork.solarssh.service.SolarSshService;

/**
 * Websocket endpoint for SolarSSH connections.
 * 
 * @author matt
 * @version 1.1
 */
public class SolarSshEndpoint extends Endpoint implements MessageHandler.Whole<String> {

  /** The user property for the SSH session ID. */
  public static final String SSH_SESSION_ID_USER_PROP = "session-id";

  private static final Logger LOG = LoggerFactory.getLogger(SolarSshEndpoint.class);

  private final SolarSshService solarSshService;

  private Session websocketSession;
  private SshSession sshSession;

  private Writer wsInputSink;

  @Autowired
  public SolarSshEndpoint(SolarSshService solarSshService) {
    super();
    this.solarSshService = solarSshService;
  }

  /**
   * Open a websocket connection.
   * 
   * <p>
   * When opening the connection, the ID of the session to connect to must be provided on a
   * <code>sessionId</code> query parameter. As long as a session exists with that ID, the websocket
   * will be allowed to connect.
   * </p>
   * 
   * {@inheritDoc}
   */
  @Override
  public void onOpen(Session session, EndpointConfig config) {
    Map<String, List<String>> params = session.getRequestParameterMap();
    List<String> values = params.get("sessionId");
    if (values == null || values.isEmpty()) {
      throw new AuthorizationException("Missing required sessionId parameter");
    }
    String sshSessionId = values.get(0);
    sshSession = solarSshService.findOne(sshSessionId);

    if (sshSession == null) {
      try {
        session.close(new CloseReason(
            CloseCodes.getCloseCode(SolarSshCloseCodes.AUTHENTICATION_FAILURE.getCode()),
            "Unknown session"));
      } catch (IOException e) {
        LOG.warn("Communication error closing websocket session", e);
      }
      return;
    }

    websocketSession = session;
    session.addMessageHandler(this);
  }

  @Override
  public void onClose(Session session, CloseReason closeReason) {
    LOG.debug("Websocket closed; {}; {}", sshSession, closeReason);
  }

  @Override
  public void onError(Session session, Throwable thr) {
    LOG.warn("Websocket error; {}", sshSession, thr);
  }

  /**
   * Process a text message from the websocket.
   * 
   * <p>
   * The first text message sent from any client <em>must</em> be a JSON object with authentication
   * details provided for the session. If the authentication succeeds, all subsequent text messages
   * will be sent directly to the remote shell associated with the session, and all text generated
   * by the remote shell will be sent back as text messages.
   * </p>
   * 
   * <h3>Authentication</h3>
   * 
   * <p>
   * The JSON payload must be an object with the following properties:
   * </p>
   * 
   * <dl>
   * <dt>{@literal cmd}</dt>
   * <dd>Must be equal to the string {@literal attach-ssh}.</dd>
   * <dt>{@literal data}</dt>
   * <dd>A nested object with authentication details and optional terminal settings.</dd>
   * </dl>
   * 
   * <p>
   * The {@literal data} object must be an object with the following properties:
   * </p>
   * 
   * <dl>
   * <dt>{@literal authorization}</dt>
   * <dd>A SNWS2 authorization header string, suitable for passing to the
   * {@link SolarSshService#attachTerminal} method.</dd>
   * <dt>{@literal authorization-date}</dt>
   * <dd>The authorization date as a number, as milliseconds since the epoch.</dd>
   * <dt>{@literal username}</dt>
   * <dd>A string node SSH username to use when attaching the remote shell terminal.</dd>
   * <dt>{@literal password}</dt>
   * <dd>A string node SSH password to use when attaching the remote shell terminal.</dd>
   * </dl>
   * 
   * <p>
   * In addition, the following optional properties may be provided:
   * </p>
   * 
   * <dl>
   * <dt>{@literal term}</dt>
   * <dd>A string value to pass as the remote shell terminal type. Defaults to
   * {@literal xterm}.</dd>
   * <dt>{@literal cols}</dt>
   * <dd>A number for the number of columns to use for the remote shell terminal. Defaults to
   * {@literal 80}.</dd>
   * <dt>{@literal lines}</dt>
   * <dd>The number of lines to use for the remote shell terminal. Defaults to {@literal 24}.</dd>
   * <dt>{@literal width}</dt>
   * <dd>A number width in pixels to use for the remote shell terminal. Defaults to
   * {@literal 640}.</dd>
   * <dt>{@literal height}</dt>
   * <dd>A number height in pixels to use for the remote shell terminal. Defaults to
   * {@literal 480}.</dd>
   * <dt>{@literal environment}</dt>
   * <dd>An object whose key/value pairs will be passed as environment variables on the remote
   * shell.</dd>
   * </dl>
   */
  @Override
  public void onMessage(String msg) {
    if (wsInputSink != null) {
      try {
        wsInputSink.write(msg);
        wsInputSink.flush();
      } catch (IOException e) {
        LOG.warn("IOException for node {} session {}", sshSession.getNodeId(), sshSession.getId(),
            e);
      }
      return;
    }
    authenticate(msg);
  }

  private void authenticate(String msg) {
    CloseReason closeReason = null;
    try {
      Map<String, ?> msgData = JsonUtils.getStringMap(msg);
      if (msgData == null) {
        throw new IllegalArgumentException("Message not provided");
      }
      Object cmd = msgData.get("cmd");
      if (!"attach-ssh".equals(cmd)) {
        throw new IllegalArgumentException("'attach-ssh' message not provided; got " + cmd);
      }
      Object data = msgData.get("data");
      if (!(data instanceof Map)) {
        throw new IllegalArgumentException("'attach-ssh' data not provided");
      }
      Map<?, ?> dataMap = (Map<?, ?>) data;
      Object auth = dataMap.get("authorization");
      Object authDate = dataMap.get("authorization-date");
      if (!(auth instanceof String && authDate instanceof Number)) {
        throw new IllegalArgumentException(
            "'attach-ssh' authorization or authorization-date data not provided");
      }

      Object uname = dataMap.get("username");
      Object pass = dataMap.get("password");
      // TODO: keypair dataMap.get("keypair");

      SshCredentials creds;
      if (uname != null) {
        creds = new SshCredentials(uname.toString(), (pass != null ? pass.toString() : null));
      } else {
        throw new AuthorizationException("'attach-ssh' credentials not provided");
      }

      SshTerminalSettings termSettings = settingsFromMap(dataMap);

      PipedInputStream sshStdin = new PipedInputStream();
      PipedOutputStream pipeOut = new PipedOutputStream(sshStdin);

      wsInputSink = new OutputStreamWriter(pipeOut, "UTF-8");

      OutputStream sshStdout = new AsyncTextOutputStream(websocketSession);

      SshSession session = solarSshService.attachTerminal(sshSession.getId(),
          ((Number) authDate).longValue(), auth.toString(), creds, termSettings, sshStdin,
          sshStdout);
      sshSession = session;

      Map<String, Object> resultMsg = new LinkedHashMap<>(2);
      resultMsg.put("success", true);
      resultMsg.put("message", "Ready to attach");

      websocketSession.getAsyncRemote().sendText(JsonUtils.getJSONString(resultMsg,
          "{\"success\":false,\"message\":\"Error serializing JSON response\"}"));
    } catch (AuthorizationException e) {
      closeReason = new CloseReason(SolarSshCloseCodes.AUTHENTICATION_FAILURE, e.getMessage());
    } catch (IllegalArgumentException e) {
      closeReason = new CloseReason(CloseReason.CloseCodes.PROTOCOL_ERROR, e.getMessage());
    } catch (SshException e) {
      switch (e.getDisconnectCode()) {
        case SshConstants.SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE:
        case SshConstants.SSH2_DISCONNECT_ILLEGAL_USER_NAME:
          // bad credentials
          closeReason = new CloseReason(SolarSshCloseCodes.AUTHENTICATION_FAILURE,
              "Bad credentials");
          break;

        default:
          closeReason = new CloseReason(CloseReason.CloseCodes.CLOSED_ABNORMALLY, e.getMessage());

      }
    } catch (IOException e) {
      LOG.error("IOException for node {} session {}", sshSession.getNodeId(), sshSession.getId(),
          e);
      closeReason = new CloseReason(CloseReason.CloseCodes.CLOSED_ABNORMALLY, e.getMessage());
    } finally {
      if (closeReason != null) {
        try {
          websocketSession.close(closeReason);
        } catch (IOException ioe) {
          LOG.warn("Communication error closing websocket session", ioe);
        }
      }
    }
  }

  private SshTerminalSettings settingsFromMap(Map<?, ?> dataMap) {
    SshTerminalSettings termSettings = new SshTerminalSettings();
    Object val = dataMap.get("term");
    if (val != null) {
      termSettings.setType(val.toString());
    }
    val = dataMap.get("cols");
    if (val instanceof Number) {
      termSettings.setCols(((Number) val).intValue());
    }
    val = dataMap.get("lines");
    if (val instanceof Number) {
      termSettings.setLines(((Number) val).intValue());
    }
    val = dataMap.get("width");
    if (val instanceof Number) {
      termSettings.setWidth(((Number) val).intValue());
    }
    val = dataMap.get("height");
    if (val instanceof Number) {
      termSettings.setHeight(((Number) val).intValue());
    }
    val = dataMap.get("environment");
    if (val instanceof Map) {
      ((Map<?, ?>) val).forEach((k, v) -> {
        if (k != null && v != null) {
          termSettings.getEnvironment().put(k.toString(), v.toString());
        }
      });
    }
    return termSettings;
  }

}
