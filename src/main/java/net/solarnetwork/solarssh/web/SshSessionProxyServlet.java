/* ==================================================================
 * SshSessionProxyServlet.java - 24/06/2017 5:03:03 PM
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

import static java.util.Collections.singletonList;

import java.net.HttpCookie;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.http.Header;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHeader;
import org.mitre.dsmiley.httpproxy.ProxyServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.solarnetwork.solarssh.domain.SshSession;

/**
 * Extension of {@link ProxyServlet} to associate with a specific {@link SshSession}.
 * 
 * @author matt
 * @version 1.2
 */
public class SshSessionProxyServlet extends ProxyServlet {

  private static final long serialVersionUID = 1273522570866832919L;

  private static final Logger LOG = LoggerFactory.getLogger(SshSessionProxyServlet.class);

  private final SshSession session;
  private final ServletConfig servletConfig;
  private final String proxyPath;

  private static class StaticServletConfig implements ServletConfig {

    @Override
    public String getServletName() {
      return "SshSessionProxyServlet";
    }

    @Override
    public ServletContext getServletContext() {
      return null;
    }

    @Override
    public Enumeration<String> getInitParameterNames() {
      return null;
    }

    @Override
    public String getInitParameter(String name) {
      return null;
    }
  }

  private static final ServletConfig GLOBAL_SERVLET_CONFIG = new StaticServletConfig();

  /**
   * Constructor.
   * 
   * @param session
   *        the session to proxy for
   * @param proxyPath
   *        the proxy path, to remove from all proxied requests
   */
  public SshSessionProxyServlet(SshSession session, String proxyPath) {
    super();
    this.session = session;
    this.proxyPath = proxyPath;
    this.servletConfig = GLOBAL_SERVLET_CONFIG;

    // configure some additional no-copy headers
    String[] headers = new String[] { HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN };
    for (String header : headers) {
      hopByHopHeaders.addHeader(new BasicHeader(header, null));
    }
  }

  @Override
  public ServletConfig getServletConfig() {
    return servletConfig;
  }

  @Override
  protected HttpClient buildHttpClient(HttpClientBuilder clientBuilder) {
    // @formatter:off
    return clientBuilder
        .setDefaultHeaders(singletonList(new BasicHeader("X-Forwarded-Path", proxyPath)))
        .setConnectionTimeToLive(1, TimeUnit.MINUTES)
        .disableCookieManagement()
        .disableRedirectHandling()
        .build();
    // @formatter:on
  }

  @Override
  protected void copyProxyCookie(HttpServletRequest servletRequest,
      HttpServletResponse servletResponse, String headerValue) {
    List<HttpCookie> cookies = HttpCookie.parse(headerValue);
    String path = proxyPath;
    if (!path.endsWith("/")) {
      path += "/";
    }
    for (HttpCookie cookie : cookies) {
      Cookie responseCookie = new Cookie(cookie.getName(), cookie.getValue());
      responseCookie.setMaxAge((int) cookie.getMaxAge());
      responseCookie.setPath(path);
      responseCookie.setHttpOnly(cookie.isHttpOnly());
      responseCookie.setSecure(cookie.getSecure());
      LOG.debug("Remapped cookie {} path to {}", cookie, proxyPath);
      servletResponse.addCookie(responseCookie);
    }
  }

  @Override
  protected void copyResponseHeader(HttpServletRequest servletRequest,
      HttpServletResponse servletResponse, Header header) {
    if (LOG.isTraceEnabled()) {
      String headerName = header.getName();
      if (hopByHopHeaders.containsHeader(headerName)) {
        return;
      }
      String headerValue = header.getValue();
      LOG.trace("Coying response header {}: {}", headerName, headerValue);
    }
    super.copyResponseHeader(servletRequest, servletResponse, header);
  }

  @Override
  protected String getTargetUri(HttpServletRequest servletRequest) {
    String targetUri = (String) servletRequest.getAttribute(ATTR_TARGET_URI);
    String requestUri = servletRequest.getRequestURI();
    if (requestUri.startsWith(proxyPath) && requestUri.length() > proxyPath.length()) {
      targetUri += requestUri.substring(proxyPath.length() - 1);
    }
    return targetUri;
  }

  @Override
  protected String rewriteUrlFromResponse(HttpServletRequest servletRequest, String theUrl) {
    int redirectUrlPos = theUrl.indexOf("://");
    if (redirectUrlPos >= 0) {
      redirectUrlPos = theUrl.indexOf("/", redirectUrlPos + 3);
    }
    if (redirectUrlPos < 0) {
      redirectUrlPos = 0;
    }

    StringBuffer curUrl = servletRequest.getRequestURL();
    int pos = curUrl.indexOf("://");
    if (pos >= 0) {
      if ((pos = curUrl.indexOf("/", pos + 3)) >= 0) {
        curUrl.setLength(pos);
      }
    }
    if (!theUrl.startsWith(proxyPath, redirectUrlPos)) {
      curUrl.append(proxyPath);
    }
    curUrl.append(theUrl, redirectUrlPos, theUrl.length());
    theUrl = curUrl.toString();

    return theUrl;
  }

  @Override
  protected String getConfigParam(String key) {
    switch (key) {
      case ProxyServlet.P_TARGET_URI:
        return "http://127.0.0.1:" + session.getReverseHttpPort();

      case ProxyServlet.P_CONNECTTIMEOUT:
        return "30000";

      case ProxyServlet.P_PRESERVECOOKIES:
        return Boolean.TRUE.toString();

      default:
        return null;
    }
  }

  /**
   * Get the session this proxy is associated with.
   * 
   * @return the session
   */
  public SshSession getSession() {
    return session;
  }

}
