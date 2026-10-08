/* ==================================================================
 * AsyncPasswordAuthenticatorTests.java - 8/10/2026 5:30:00 PM
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

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test cases for the {@link AsyncPasswordAuthenticator} class.
 * 
 * @author matt
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
public class AsyncPasswordAuthenticatorTests {

  private static final String USERNAME = "123:token";
  private static final String PASSWORD = "secret";

  @Mock
  private PasswordAuthenticator delegate;

  @Mock
  private ServerSession session;

  private ExecutorService executor;
  private AsyncPasswordAuthenticator auth;

  @BeforeEach
  public void setup() {
    executor = Executors.newCachedThreadPool();
    auth = new AsyncPasswordAuthenticator(delegate, executor);
  }

  @AfterEach
  public void teardown() {
    executor.shutdownNow();
  }

  private CompletableFuture<Boolean> asyncResult(ServerSession sess) {
    AsyncAuthException async = assertThrows(AsyncAuthException.class,
        () -> auth.authenticate(USERNAME, PASSWORD, sess), "Authentication is asynchronous");
    CompletableFuture<Boolean> result = new CompletableFuture<>();
    async.addListener(result::complete);
    return result;
  }

  @Test
  public void success() throws Exception {
    // GIVEN
    AtomicReference<Thread> delegateThread = new AtomicReference<>();
    given(delegate.authenticate(USERNAME, PASSWORD, session)).willAnswer(invocation -> {
      delegateThread.set(Thread.currentThread());
      return true;
    });

    // WHEN
    CompletableFuture<Boolean> result = asyncResult(session);

    // THEN
    assertTrue(result.get(5, SECONDS), "Delegate success passed through");
    assertNotSame(Thread.currentThread(), delegateThread.get(),
        "Delegate invoked on executor thread");
  }

  @Test
  public void failure() throws Exception {
    // GIVEN
    given(delegate.authenticate(USERNAME, PASSWORD, session)).willReturn(false);

    // WHEN
    CompletableFuture<Boolean> result = asyncResult(session);

    // THEN
    assertFalse(result.get(5, SECONDS), "Delegate failure passed through");
  }

  @Test
  public void delegateThrows() throws Exception {
    // GIVEN
    given(delegate.authenticate(USERNAME, PASSWORD, session))
        .willThrow(new RuntimeSshException("Communication error"));

    // WHEN
    CompletableFuture<Boolean> result = asyncResult(session);

    // THEN
    assertFalse(result.get(5, SECONDS), "Delegate exception treated as failure");
  }

  @Test
  public void executorRejects() {
    // GIVEN
    auth = new AsyncPasswordAuthenticator(delegate, task -> {
      throw new RejectedExecutionException("Full");
    });

    // WHEN
    boolean result = auth.authenticate(USERNAME, PASSWORD, session);

    // THEN
    assertFalse(result, "Rejected attempt fails immediately");
    then(delegate).shouldHaveNoInteractions();
  }

  @Test
  public void oneAttemptAtATimePerSession() throws Exception {
    // GIVEN
    CountDownLatch release = new CountDownLatch(1);
    given(delegate.authenticate(USERNAME, PASSWORD, session)).willAnswer(invocation -> {
      return release.await(5, SECONDS);
    });
    ServerSession otherSession = mock(ServerSession.class);
    given(delegate.authenticate(USERNAME, PASSWORD, otherSession)).willReturn(true);

    // WHEN
    final CompletableFuture<Boolean> first = asyncResult(session);
    boolean second = auth.authenticate(USERNAME, PASSWORD, session);
    CompletableFuture<Boolean> other = asyncResult(otherSession);

    // THEN
    assertFalse(second, "Second attempt on session fails while first is in progress");
    assertTrue(other.get(5, SECONDS), "Attempt on another session is not affected");
    release.countDown();
    assertTrue(first.get(5, SECONDS), "First attempt completes");
    then(delegate).should().authenticate(USERNAME, PASSWORD, session);

    // WHEN
    CompletableFuture<Boolean> third = asyncResult(session);

    // THEN
    assertTrue(third.get(5, SECONDS), "Attempt after the first completes is accepted");
  }

}
