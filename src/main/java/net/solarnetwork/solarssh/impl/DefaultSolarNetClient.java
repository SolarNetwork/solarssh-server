/* ==================================================================
 * DefaultSolarNetClient.java - 17/06/2017 10:24:37 AM
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

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.FileCopyUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.solarnetwork.domain.datum.GeneralDatumMetadata;
import net.solarnetwork.service.support.HttpClientSupport;
import net.solarnetwork.solarssh.AuthorizationException;
import net.solarnetwork.solarssh.domain.SolarNetInstruction;
import net.solarnetwork.solarssh.service.SolarNetClient;
import net.solarnetwork.web.jakarta.security.WebConstants;

/**
 * Default implementation of {@link SolarNetClient}.
 * 
 * @author matt
 * @version 1.1
 */
public class DefaultSolarNetClient extends HttpClientSupport implements SolarNetClient {

  private static final Pattern SIGNED_HEADERS_PATTERN = Pattern.compile(",SignedHeaders=([^,]+),");
  private static final ObjectMapper MAPPER = new ObjectMapper();

  static {
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS'Z'");
    sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
    MAPPER.setDateFormat(sdf);
    MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  private static final SniListTypeReference SNI_LIST_TYPE = new SniListTypeReference();

  private String apiBaseUrl = "https://data.solarnetwork.net";
  private String viewPendingInstructionsPath = "/solaruser/api/v1/sec/instr/viewPending";
  private String getInstructionPath = "/solaruser/api/v1/sec/instr/view";
  private String queueInstructionPath = "/solaruser/api/v1/sec/instr/add";
  private String viewNodeMetadataPath = "/solaruser/api/v1/sec/nodes/meta/";

  private static String uriHost(URI uri) {
    String host = uri.getHost();
    if (uri.getPort() != 80 && uri.getPort() != 443) {
      host += ":" + uri.getPort();
    }
    return host;
  }

  private static final class SniListTypeReference extends TypeReference<List<SolarNetInstruction>> {

    private SniListTypeReference() {
      super();
    }

  }

  /**
   * Initialize the service after all properties configured.
   */
  public void init() {
    log.info("SolarNetClient configured with API url {}", apiBaseUrl);
  }

  private URI apiUri(String path) {
    URI uri;
    try {
      uri = new URI(apiBaseUrl + path);
    } catch (URISyntaxException e) {
      throw new RuntimeException("Error in configured URL settings for queuing instructions", e);
    }
    return uri;
  }

  @Override
  public List<SolarNetInstruction> pendingInstructions(Long nodeId, long authorizationDate,
      String authorization) throws IOException {
    String dateHeaderName = signedDateHeaderName(authorization);
    URI uri = apiUri(viewPendingInstructionsPath + "?nodeId=" + nodeId);

    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.HOST, uriHost(uri));
    headers.setDate(dateHeaderName, authorizationDate);
    headers.set(HttpHeaders.AUTHORIZATION, authorization);

    URLConnection conn = get(uri, MediaType.APPLICATION_JSON_VALUE, headers);
    JsonNode node = MAPPER.readTree(getInputStreamFromURLConnection(conn));
    if (log.isTraceEnabled()) {
      log.trace("Got pending instructions JSON: {}", MAPPER.writeValueAsString(node));
    }
    JsonNode data = node.path("data");
    List<SolarNetInstruction> results;
    if (data.isArray()) {
      return MAPPER.readValue(MAPPER.treeAsTokens(data), SNI_LIST_TYPE);
    } else {
      results = Collections.emptyList();
    }
    return results;
  }

  @Override
  public SolarNetInstruction getInstruction(Long id, long authorizationDate, String authorization)
      throws IOException {
    String dateHeaderName = signedDateHeaderName(authorization);
    URI uri = apiUri(getInstructionPath + "?id=" + id);

    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.HOST, uriHost(uri));
    headers.setDate(dateHeaderName, authorizationDate);
    headers.set(HttpHeaders.AUTHORIZATION, authorization);

    URLConnection conn = get(uri, MediaType.APPLICATION_JSON_VALUE, headers);
    JsonNode node = MAPPER.readTree(getInputStreamFromURLConnection(conn));
    if (log.isTraceEnabled()) {
      log.trace("Got instructions JSON: {}", MAPPER.writeValueAsString(node));
    }
    JsonNode data = node.path("data");
    SolarNetInstruction result = MAPPER.readValue(MAPPER.treeAsTokens(data),
        SolarNetInstruction.class);
    return result;
  }

  @Override
  public Long queueInstruction(String topic, Long nodeId, Map<String, ?> parameters,
      long authorizationDate, String authorization) throws IOException {
    URI uri = apiUri(queueInstructionPath);

    Map<String, Object> params = new LinkedHashMap<>(parameters);
    params.put("nodeId", nodeId);
    params.put("topic", topic);

    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.HOST, uriHost(uri));
    headers.setDate(signedDateHeaderName(authorization), authorizationDate);
    headers.set(HttpHeaders.AUTHORIZATION, authorization);
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    URLConnection conn = postForm(uri, MediaType.APPLICATION_JSON_VALUE, headers, params);

    JsonNode node = MAPPER.readTree(getInputStreamFromURLConnection(conn));
    if (log.isTraceEnabled()) {
      log.trace("Got pending instructions JSON: {}", MAPPER.writeValueAsString(node));
    }
    Number id = node.findPath("id").numberValue();
    return (id != null ? id.longValue() : null);
  }

  @Override
  public GeneralDatumMetadata getNodeMetadata(Long nodeId, long authorizationDate,
      String authorization) throws IOException {
    URI uri = apiUri(viewNodeMetadataPath + nodeId);

    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.HOST, uriHost(uri));
    headers.setDate(signedDateHeaderName(authorization), authorizationDate);
    headers.set(HttpHeaders.AUTHORIZATION, authorization);

    URLConnection conn = get(uri, MediaType.APPLICATION_JSON_VALUE, headers);
    JsonNode node = MAPPER.readTree(getInputStreamFromURLConnection(conn));
    if (log.isTraceEnabled()) {
      log.trace("Got node metadata JSON: {}", MAPPER.writeValueAsString(node));
    }
    JsonNode data = node.path("data");
    GeneralDatumMetadata result;
    if (data.isObject()) {
      return MAPPER.treeToValue(data, GeneralDatumMetadata.class);
    } else {
      result = new GeneralDatumMetadata();
    }
    return result;
  }

  private String signedDateHeaderName(String authorization) {
    if (authorization == null) {
      throw new AuthorizationException("Authorization missing");
    }
    Matcher signedHeaders = SIGNED_HEADERS_PATTERN.matcher(authorization);
    if (!signedHeaders.find()) {
      throw new AuthorizationException("SignedHeaders missing");
    }
    String[] signedHeaderNames = signedHeaders.group(1).split(";");
    int dateHeaderIndex = Arrays.binarySearch(signedHeaderNames, "x-sn-date");
    if (dateHeaderIndex < 0) {
      dateHeaderIndex = Arrays.binarySearch(signedHeaderNames, "date");
    }
    if (dateHeaderIndex < 0) {
      throw new AuthorizationException(
          "Date or X-SN-Date signed header name missing; available headers: "
              + signedHeaders.group(1));
    }
    String dateHeaderName;
    switch (signedHeaderNames[dateHeaderIndex]) {
      case "date":
        dateHeaderName = "Date";
        break;
      default:
        dateHeaderName = WebConstants.HEADER_DATE;
    }
    return dateHeaderName;
  }

  protected URLConnection postForm(URI uri, String accept, HttpHeaders headers, Map<String, ?> data)
      throws IOException {
    URLConnection conn = getURLConnection(uri.toString(), HTTP_METHOD_POST, accept);
    if (headers != null) {
      log.trace("Adding HTTP POST headers {}", headers);
      for (Map.Entry<String, String> me : headers.toSingleValueMap().entrySet()) {
        conn.setRequestProperty(me.getKey(), me.getValue());
      }
    }
    String body = xWWWFormURLEncoded(data);
    log.trace("Encoded HTTP POST data {} for {} as {}", data, uri, body);
    OutputStreamWriter out = new OutputStreamWriter(conn.getOutputStream(), "UTF-8");
    FileCopyUtils.copy(new StringReader(body), out);
    if (conn instanceof HttpURLConnection) {
      HttpURLConnection http = (HttpURLConnection) conn;
      int status = http.getResponseCode();
      if (status == 401 || status == 403) {
        throw new AuthorizationException("HTTP request denied.");
      } else if (status < 200 || status > 299) {
        throw new IOException("HTTP result status not in the 200-299 range: "
            + http.getResponseCode() + " " + http.getResponseMessage());
      }
    }
    return conn;
  }

  protected URLConnection get(URI uri, String accept, HttpHeaders headers) throws IOException {
    URLConnection conn = getURLConnection(uri.toString(), HTTP_METHOD_GET, accept);
    if (headers != null) {
      log.trace("Adding HTTP GET headers {}", headers);
      for (Map.Entry<String, String> me : headers.toSingleValueMap().entrySet()) {
        conn.setRequestProperty(me.getKey(), me.getValue());
      }
    }
    if (conn instanceof HttpURLConnection) {
      HttpURLConnection http = (HttpURLConnection) conn;
      int status = http.getResponseCode();
      if (status == 401 || status == 403) {
        throw new AuthorizationException("HTTP request denied.");
      } else if (status < 200 || status > 299) {
        throw new IOException("HTTP result status not in the 200-299 range: "
            + http.getResponseCode() + " " + http.getResponseMessage());
      }
    }
    return conn;
  }

  public void setApiBaseUrl(String apiBaseUrl) {
    this.apiBaseUrl = apiBaseUrl;
  }

  public void setQueueInstructionPath(String queueInstructionPath) {
    this.queueInstructionPath = queueInstructionPath;
  }

  public void setViewPendingInstructionsPath(String viewPendingInstructionsPath) {
    this.viewPendingInstructionsPath = viewPendingInstructionsPath;
  }

  public void setViewNodeMetadataPath(String viewNodeMetadataPath) {
    this.viewNodeMetadataPath = viewNodeMetadataPath;
  }

  public void setGetInstructionPath(String getInstructionPath) {
    this.getInstructionPath = getInstructionPath;
  }

}
