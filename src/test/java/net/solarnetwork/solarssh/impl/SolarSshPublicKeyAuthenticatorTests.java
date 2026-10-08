/* ==================================================================
 * SolarSshPublicKeyAuthenticatorTests.java - 9/10/2026 10:41:27 AM
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

import static org.apache.sshd.common.keyprovider.KeyPairProvider.SSH_ED25519;
import static org.apache.sshd.common.keyprovider.KeyPairProvider.SSH_RSA;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verifyNoInteractions;

import java.security.PublicKey;
import java.util.UUID;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.server.session.ServerSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import net.solarnetwork.solarssh.dao.SolarNodeDao;
import net.solarnetwork.solarssh.dao.SshSessionDao;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * Test cases for the {@link SolarSshPublicKeyAuthenticator} class.
 *
 * @author matt
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
public class SolarSshPublicKeyAuthenticatorTests {

  private static final Long TEST_NODE_ID = 123L;

  @Mock
  private SshSessionDao sessionDao;

  @Mock
  private SolarNodeDao nodeDao;

  @Mock
  private ServerSession serverSession;

  private SshSession sess;
  private SolarSshPublicKeyAuthenticator auth;

  @BeforeEach
  public void setup() {
    sess = new SshSession(System.currentTimeMillis(), UUID.randomUUID().toString(), TEST_NODE_ID,
        "localhost", 8022, 50000, 50001);
    auth = new SolarSshPublicKeyAuthenticator(sessionDao, nodeDao);
  }

  private static PublicKey newKey(String keyType, int keySize) throws Exception {
    return KeyUtils.generateKeyPair(keyType, keySize).getPublic();
  }

  @Test
  public void unknownSession() throws Exception {
    // GIVEN
    PublicKey key = newKey(SSH_ED25519, 256);

    // WHEN
    boolean result = auth.authenticate(sess.getId(), key, serverSession);

    // THEN
    assertFalse(result, "Unknown session rejected");
    verifyNoInteractions(nodeDao);
  }

  @Test
  public void matchingKey_ed25519() throws Exception {
    // GIVEN
    PublicKey key = newKey(SSH_ED25519, 256);
    given(sessionDao.findOne(sess.getId())).willReturn(sess);
    given(nodeDao.findSshPublicKey(TEST_NODE_ID))
        .willReturn(PublicKeyEntry.toString(key) + " solar@solarnode");

    // WHEN
    boolean result = auth.authenticate(sess.getId(), key, serverSession);

    // THEN
    assertTrue(result, "Key matching published key accepted");
  }

  @Test
  public void matchingKey_rsa() throws Exception {
    // GIVEN
    PublicKey key = newKey(SSH_RSA, 2048);
    given(sessionDao.findOne(sess.getId())).willReturn(sess);
    given(nodeDao.findSshPublicKey(TEST_NODE_ID)).willReturn(PublicKeyEntry.toString(key));

    // WHEN
    boolean result = auth.authenticate(sess.getId(), key, serverSession);

    // THEN
    assertTrue(result, "Key matching published key accepted");
  }

  @Test
  public void mismatchedKey() throws Exception {
    // GIVEN
    PublicKey key = newKey(SSH_ED25519, 256);
    PublicKey published = newKey(SSH_ED25519, 256);
    given(sessionDao.findOne(sess.getId())).willReturn(sess);
    given(nodeDao.findSshPublicKey(TEST_NODE_ID)).willReturn(PublicKeyEntry.toString(published));

    // WHEN
    boolean result = auth.authenticate(sess.getId(), key, serverSession);

    // THEN
    assertFalse(result, "Key not matching published key rejected");
  }

  @Test
  public void noPublishedKey() throws Exception {
    // GIVEN
    PublicKey key = newKey(SSH_ED25519, 256);
    given(sessionDao.findOne(sess.getId())).willReturn(sess);
    given(nodeDao.findSshPublicKey(TEST_NODE_ID)).willReturn(null);

    // WHEN
    boolean result = auth.authenticate(sess.getId(), key, serverSession);

    // THEN
    assertFalse(result, "Key rejected when node has not published one");
  }

  @Test
  public void invalidPublishedKey() throws Exception {
    // GIVEN
    PublicKey key = newKey(SSH_ED25519, 256);
    given(sessionDao.findOne(sess.getId())).willReturn(sess);
    given(nodeDao.findSshPublicKey(TEST_NODE_ID)).willReturn("ssh-ed25519 not-a-key");

    // WHEN
    boolean result = auth.authenticate(sess.getId(), key, serverSession);

    // THEN
    assertFalse(result, "Key rejected when published key cannot be parsed");
  }

  @Test
  public void lookupError() throws Exception {
    // GIVEN
    PublicKey key = newKey(SSH_ED25519, 256);
    given(sessionDao.findOne(sess.getId())).willReturn(sess);
    given(nodeDao.findSshPublicKey(TEST_NODE_ID)).willThrow(new RuntimeException("Boom"));

    // WHEN
    boolean result = auth.authenticate(sess.getId(), key, serverSession);

    // THEN
    assertFalse(result, "Key rejected when published key cannot be looked up");
  }

  @Test
  public void noVerification() throws Exception {
    // GIVEN
    auth = new SolarSshPublicKeyAuthenticator(sessionDao, null);
    PublicKey key = newKey(SSH_ED25519, 256);
    given(sessionDao.findOne(sess.getId())).willReturn(sess);

    // WHEN
    boolean result = auth.authenticate(sess.getId(), key, serverSession);

    // THEN
    assertTrue(result, "Any key accepted when verification disabled");
  }

}
