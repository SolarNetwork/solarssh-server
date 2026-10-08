/* ==================================================================
 * AsyncPasswordAuthenticator.java - 8/10/2026 5:30:00 PM
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

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link PasswordAuthenticator} that runs a delegate authenticator on an {@link Executor}.
 * 
 * <p>
 * The SSH server invokes authenticators on its I/O processor threads: a small, fixed pool where
 * each thread also services every other connection assigned to it. A delegate that can take a long
 * time, such as {@link SolarSshPasswordAuthenticator} waiting for a node to connect, would stall
 * all of those connections. This class instead runs the delegate on the executor and throws an
 * {@link AsyncAuthException}, which the SSH server completes once the delegate returns.
 * </p>
 * 
 * <p>
 * The delegate is expected to be synchronous, and any exception it throws is treated as an
 * authentication failure. Only one authentication can be in progress per session: any further
 * attempt made while one is in progress fails immediately, without invoking the delegate.
 * </p>
 * 
 * @author matt
 * @version 1.0
 */
public class AsyncPasswordAuthenticator implements PasswordAuthenticator {

  private static final Logger log = LoggerFactory.getLogger(AsyncPasswordAuthenticator.class);

  private final PasswordAuthenticator delegate;
  private final Executor executor;
  private final Set<ServerSession> pending = ConcurrentHashMap.newKeySet();

  /**
   * Constructor.
   * 
   * @param delegate
   *        the authenticator to run on the executor
   * @param executor
   *        the executor to use; if it rejects a task the authentication attempt fails
   * @throws IllegalArgumentException
   *         if any argument is {@literal null}
   */
  public AsyncPasswordAuthenticator(PasswordAuthenticator delegate, Executor executor) {
    super();
    if (delegate == null) {
      throw new IllegalArgumentException("The delegate argument must not be null.");
    }
    if (executor == null) {
      throw new IllegalArgumentException("The executor argument must not be null.");
    }
    this.delegate = delegate;
    this.executor = executor;
  }

  @Override
  public boolean authenticate(String username, String password, ServerSession session)
      throws PasswordChangeRequiredException, AsyncAuthException {
    if (!pending.add(session)) {
      log.info("Rejecting authentication attempt [{}] from {}: another is already in progress",
          username, session.getRemoteAddress());
      return false;
    }
    final AsyncAuthException result = new AsyncAuthException();
    try {
      executor.execute(() -> doAuthenticate(username, password, session, result));
    } catch (RejectedExecutionException e) {
      pending.remove(session);
      log.warn("Rejecting authentication attempt [{}] from {}: no capacity to process it",
          username, session.getRemoteAddress());
      return false;
    }
    throw result;
  }

  private void doAuthenticate(String username, String password, ServerSession session,
      AsyncAuthException result) {
    boolean authed = false;
    try {
      authed = delegate.authenticate(username, password, session);
    } catch (Exception e) {
      log.warn("Authentication attempt [{}] from {} failed: {}", username,
          session.getRemoteAddress(), e.toString());
    } finally {
      // clear before completing, so a retry sent as soon as the client sees the result is accepted
      pending.remove(session);
      result.setAuthed(authed);
    }
  }

}
