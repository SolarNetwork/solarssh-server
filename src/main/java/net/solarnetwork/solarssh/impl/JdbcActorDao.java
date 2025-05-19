/* ==================================================================
 * JdbcActorDao.java - 11/08/2020 11:33:29 AM
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

package net.solarnetwork.solarssh.impl;

import static java.time.Instant.now;
import static net.solarnetwork.solarssh.Globals.DEFAULT_SN_HOST;
import static net.solarnetwork.util.StringUtils.delimitedStringToMap;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import javax.cache.Cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementCreator;

import net.solarnetwork.security.Snws2AuthorizationBuilder;
import net.solarnetwork.solarssh.dao.ActorDao;
import net.solarnetwork.solarssh.domain.Actor;
import net.solarnetwork.solarssh.domain.SnTokenDetails;

/**
 * JDBC implementation of {@link ActorDao}.
 * 
 * @author matt
 * @version 1.2
 */
public class JdbcActorDao implements ActorDao {

  /**
   * The default value for the {@code snHost} property.
   */
  public static final String DEFAULT_SN_PATH = "/solarssh/auth";

  /**
   * The SNWS2 authorization token for the signature value.
   */
  public static final String SIGNATURE_TOKEN = "Signature";

  // CHECKSTYLE OFF: LineLength

  /**
   * The default value for the {@code authenticateCall} property.
   */
  public static final String DEFAULT_AUTHENTICATE_CALL = "SELECT user_id,token_type,jpolicy FROM solaruser.snws2_find_verified_token_details(?,?,?,?,?)";

  /**
   * The default value for the {@code authorizeCall} property.
   */
  public static final String DEFAULT_AUTHORIZE_CALL = "SELECT user_id,token_type,jpolicy,node_ids FROM solaruser.user_auth_token_node_ids WHERE auth_token = ?";

  // CHECKSTYLE ON: LineLength

  private static final Logger log = LoggerFactory.getLogger(JdbcActorDao.class);

  private final JdbcOperations jdbcOps;
  private String authenticateCall = DEFAULT_AUTHENTICATE_CALL;
  private String authorizeCall = DEFAULT_AUTHORIZE_CALL;
  private String snHost = DEFAULT_SN_HOST;
  private String snPath = DEFAULT_SN_PATH;
  private Cache<String, Actor> actorCache;

  /**
   * Constructor.
   * 
   * @param jdbcOps
   *        the JDBC ops to use
   */
  public JdbcActorDao(JdbcOperations jdbcOps) {
    super();
    this.jdbcOps = jdbcOps;
  }

  @Override
  public Actor getAuthenticatedActor(final Long nodeId, final String tokenId,
      final String tokenSecret) {
    SnTokenDetails authentication = authenticateToken(tokenId, tokenSecret);
    if (authentication == null) {
      return null;
    }
    Actor actor = actor(tokenId);
    if (actor.getAllowedNodeIds() == null || !actor.getAllowedNodeIds().contains(nodeId)) {
      return null;
    }
    return actor;
  }

  private SnTokenDetails authenticateToken(String tokenId, String tokenSecret) {
    log.debug("Authenticating [{}] @ {}{}", tokenId, snHost, snPath);
    List<SnTokenDetails> results = jdbcOps.query(new PreparedStatementCreator() {

      @Override
      public PreparedStatement createPreparedStatement(Connection con) throws SQLException {
        final Instant now = Instant.now();
        final Snws2AuthorizationBuilder builder = new Snws2AuthorizationBuilder(tokenId)
            .useSnDate(true).date(now).host(snHost).path(snPath);
        final String auth = builder.build(tokenSecret);
        final Map<String, String> authTokens = delimitedStringToMap(auth, ",", "=");
        final Timestamp ts = Timestamp.from(now);

        PreparedStatement stmt = con.prepareStatement(authenticateCall, ResultSet.TYPE_FORWARD_ONLY,
            ResultSet.CONCUR_READ_ONLY);
        stmt.setString(1, tokenId);
        stmt.setTimestamp(2, ts);
        stmt.setString(3, snHost);
        stmt.setString(4, snPath);
        stmt.setString(5, authTokens.get(SIGNATURE_TOKEN));
        log.debug("Authenticating with SQL: {} [{},{},{},{},{}]", authenticateCall, tokenId, ts,
            snHost, snPath, authTokens.get(SIGNATURE_TOKEN));
        return stmt;
      }
    }, new SnTokenDetailsRowMapper(tokenId));

    if (results == null || results.isEmpty()) {
      return null;
    }

    // verify not expired
    SnTokenDetails details = results.get(0);
    if (details.getPolicy() != null && !details.getPolicy().isValidAt(now())) {
      return null;
    }

    return details;
  }

  private Actor actor(String tokenId) {
    final Cache<String, Actor> cache = getActorCache();
    final String actorCacheKey = cacheKeyForTokenId(tokenId);
    if (cache != null && actorCacheKey != null) {
      Actor actor = cache.get(actorCacheKey);
      if (actor != null) {
        return actor;
      }
    }
    List<Actor> results = jdbcOps.query(new PreparedStatementCreator() {

      @Override
      public PreparedStatement createPreparedStatement(Connection con) throws SQLException {
        PreparedStatement stmt = con.prepareStatement(authorizeCall, ResultSet.TYPE_FORWARD_ONLY,
            ResultSet.CONCUR_READ_ONLY);
        stmt.setString(1, tokenId);
        return stmt;
      }
    }, new ActorDetailsRowMapper(tokenId));

    if (results != null && !results.isEmpty()) {
      Actor actor = results.get(0);
      if (cache != null && actorCacheKey != null) {
        cache.put(actorCacheKey, actor);
      }
      return actor;
    }
    return null;
  }

  private String cacheKeyForTokenId(String tokenId) {
    if (tokenId == null) {
      return null;
    }
    return "Token-" + tokenId;
  }

  /**
   * Get the configured authenticate JDBC call.
   * 
   * @return the authenticate JDBC call; defaults to {@link #DEFAULT_AUTHENTICATE_CALL}
   */
  public String getAuthenticateCall() {
    return authenticateCall;
  }

  /**
   * Set the authenticate JDBC call to use.
   * 
   * <p>
   * This JDBC statement is used to authenticate requests. This JDBC statement is expected to take
   * the following parameters:
   * </p>
   * 
   * <ol>
   * <li><b>token_id</b> ({@code String}) - the SolarNetwork security token ID</li>
   * <li><b>req_date</b> ({@link Timestamp}) - the request date</li>
   * <li><b>host</b> ({@code String}) - the SolarNetwork host</li>
   * <li><b>path</b> ({@code String}) - the request path</li>
   * <li><b>signature</b> ({@code String}) - the hex-encoded SolarNetwork token signature</li>
   * </ol>
   * 
   * <p>
   * If the credentials match, a result set with the following columns is expected to be returned:
   * </p>
   * 
   * <ol>
   * <li><b>user_id</b> ({@code Long}) - the SolarNetwork user ID that owns the token</li>
   * <li><b>token_type</b> ({@code String}) - the SolarNetwork token type, e.g.
   * {@literal ReadNodeData}</li>
   * <li><b>jpolicy</b> ({@code String}) - the SolarNetwork security policy associated with the
   * token</li>
   * </ol>
   * 
   * <p>
   * If the credentials do not match, an empty result set is expected.
   * </p>
   * 
   * @param jdbcCall
   *        the JDBC call
   * @throws IllegalArgumentException
   *         if {@code jdbcCall} is {@literal null}
   */
  public void setAuthenticateCall(String jdbcCall) {
    if (jdbcCall == null) {
      throw new IllegalArgumentException("jdbcCall must not be null");
    }
    this.authenticateCall = jdbcCall;
  }

  /**
   * Get the authorization JDBC call to use.
   * 
   * @return the JDBC call; defaults to {@link #DEFAULT_AUTHORIZE_CALL}
   */
  public String getAuthorizeCall() {
    return authorizeCall;
  }

  /**
   * Set the authorization JDBC call to use.
   * 
   * <p>
   * This JDBC statement is used to authorize publish/subscribe requests. This JDBC statement is
   * expected to take the following parameters:
   * </p>
   * 
   * <ol>
   * <li><b>token_id</b> ({@code String}) - the SolarNetwork security token ID</li>
   * </ol>
   * 
   * <p>
   * A result set with the following columns is expected to be returned:
   * </p>
   * 
   * <ol>
   * <li><b>user_id</b> ({@code Long}) - the SolarNetwork user ID that owns the token</li>
   * <li><b>token_type</b> ({@code String}) - the SolarNetwork token type, e.g.
   * {@literal ReadNodeData}</li>
   * <li><b>jpolicy</b> ({@code String}) - the SolarNetwork security policy associated with the
   * token</li>
   * <li><b>node_ids</b> ({@code Long[]}) - an array of SolarNode IDs valid for this actor</li>
   * </ol>
   * 
   * <p>
   * If no token is available for {@code token_id}, an empty result set is expected.
   * </p>
   * 
   * @param jdbcCall
   *        the JDBC call
   * @throws IllegalArgumentException
   *         if {@code jdbcCall} is {@literal null}
   */
  public void setAuthorizeCall(String jdbcCall) {
    if (jdbcCall == null) {
      throw new IllegalArgumentException("jdbcCall must not be null");
    }
    this.authorizeCall = jdbcCall;
  }

  /**
   * Get the configured SolarNetwork host.
   * 
   * @return the host; defaults to {@link net.solarnetwork.solarssh.Globals#DEFAULT_SN_HOST}
   */
  public String getSnHost() {
    return snHost;
  }

  /**
   * Set the SolarNetwork host to use.
   * 
   * @param snHost
   *        the host
   * @throws IllegalArgumentException
   *         if {@code snHost} is {@literal null}
   */
  public void setSnHost(String snHost) {
    if (snHost == null) {
      throw new IllegalArgumentException("snHost must not be null");
    }
    this.snHost = snHost;
  }

  /**
   * Get the configured SolarNetwork path.
   * 
   * @return the path; defaults to {@link #DEFAULT_SN_PATH}
   */
  public String getSnPath() {
    return snPath;
  }

  /**
   * Set the SolarNetwork path to use.
   * 
   * @param snPath
   *        the path
   * @throws IllegalArgumentException
   *         if {@code snPath} is {@literal null}
   */
  public void setSnPath(String snPath) {
    if (snPath == null) {
      throw new IllegalArgumentException("snPath must not be null");
    }
    this.snPath = snPath;
  }

  /**
   * Get the configured actor cache.
   * 
   * @return the actor cache
   */
  public Cache<String, Actor> getActorCache() {
    return actorCache;
  }

  /**
   * Configure a actor cache.
   * 
   * @param actorCache
   *        the cache to use for actors
   */
  @Autowired(required = false)
  @Qualifier("actor")
  public void setActorCache(Cache<String, Actor> actorCache) {
    this.actorCache = actorCache;
  }

}
