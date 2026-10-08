/* ==================================================================
 * SolarSshPublicKeyAuthenticator.java - 21/06/2017 11:46:13 AM
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

package net.solarnetwork.solarssh.impl;

import static net.solarnetwork.codec.JsonUtils.getJSONString;
import static net.solarnetwork.solarssh.Globals.AUDIT_LOG;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Map;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.solarnetwork.solarssh.Globals;
import net.solarnetwork.solarssh.dao.SolarNodeDao;
import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * Supports SSH public key authentication for active SSH sessions.
 *
 * <p>
 * The presented {@code username} values must be existing session IDs. If a {@link SolarNodeDao}
 * is configured, the presented key must also match the SSH public key the session's node has
 * published to its metadata.
 * </p>
 *
 * @author matt
 * @version 1.1
 */
public class SolarSshPublicKeyAuthenticator implements PublickeyAuthenticator {

  /** The audit event name when a node public key is rejected. */
  public static final String AUDIT_EVENT_NODE_AUTH_FAIL = "NODE-AUTH-FAIL";

  private static final Logger log = LoggerFactory.getLogger(SolarSshPublicKeyAuthenticator.class);

  private final SshSessionDao sessionDao;
  private final SolarNodeDao nodeDao;

  /**
   * Constructor.
   *
   * @param sessionDao
   *        the DAO to access sessions with
   * @param nodeDao
   *        the DAO to access node public keys with, or {@literal null} to not verify keys
   */
  public SolarSshPublicKeyAuthenticator(SshSessionDao sessionDao, SolarNodeDao nodeDao) {
    super();
    this.sessionDao = sessionDao;
    this.nodeDao = nodeDao;
  }

  @Override
  public boolean authenticate(String username, PublicKey key, ServerSession session) {
    SshSession sess = sessionDao.findOne(username);
    if (sess == null) {
      return false;
    }
    if (nodeDao == null) {
      return true;
    }

    final String keyData;
    try {
      keyData = nodeDao.findSshPublicKey(sess.getNodeId());
    } catch (RuntimeException e) {
      log.error("Error looking up SSH public key for node {}: {}", sess.getNodeId(), e.toString());
      auditFailure(session, sess, key, "lookup-error");
      return false;
    }
    if (keyData == null || keyData.isBlank()) {
      log.warn("Node {} has not published an SSH public key; rejecting session {}",
          sess.getNodeId(), sess.getId());
      auditFailure(session, sess, key, "no-key");
      return false;
    }

    PublicKey nodeKey = null;
    try {
      AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(keyData);
      if (entry != null) {
        nodeKey = entry.resolvePublicKey(session, null, PublicKeyEntryResolver.FAILING);
      }
    } catch (IllegalArgumentException | IOException | GeneralSecurityException e) {
      log.warn("Node {} published SSH public key cannot be parsed: {}", sess.getNodeId(),
          e.toString());
    }
    if (nodeKey == null) {
      auditFailure(session, sess, key, "invalid-key");
      return false;
    }

    if (!KeyUtils.compareKeys(nodeKey, key)) {
      log.warn("Node {} session {} presented SSH public key {} that does not match published {}",
          sess.getNodeId(), sess.getId(), KeyUtils.getFingerPrint(key),
          KeyUtils.getFingerPrint(nodeKey));
      auditFailure(session, sess, key, "key-mismatch");
      return false;
    }
    return true;
  }

  private static void auditFailure(ServerSession session, SshSession sess, PublicKey key,
      String reason) {
    Map<String, Object> auditProps = Globals.auditEventMap(session, sess,
        AUDIT_EVENT_NODE_AUTH_FAIL);
    auditProps.put("remoteAddress", session.getRemoteAddress());
    auditProps.put("reason", reason);
    auditProps.put("fingerprint", KeyUtils.getFingerPrint(key));
    AUDIT_LOG.info(getJSONString(auditProps, "{}"));
  }

}
