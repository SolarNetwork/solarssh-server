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

package net.solarnetwork.solarssh.config;

import java.net.InetAddress;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.expiry.CreatedExpiryPolicy;
import javax.cache.expiry.Duration;
import javax.cache.spi.CachingProvider;

import org.ehcache.config.CacheConfiguration;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.ExpiryPolicyBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;
import org.ehcache.config.units.MemoryUnit;
import org.ehcache.core.config.DefaultConfiguration;
import org.ehcache.impl.config.persistence.DefaultPersistenceConfiguration;
import org.ehcache.jsr107.Eh107Configuration;
import org.ehcache.jsr107.EhcacheCachingProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import net.solarnetwork.solarssh.domain.Actor;

/**
 * Configuration for application-level caching.
 * 
 * @author matt
 * @version 1.0
 */
@Configuration
@EnableCaching
public class CacheConfig {

  /**
   * A cache name to use for lists of {@link Actor} objects.
   */
  public static final String ACTOR_CACHE_NAME = "Actor";

  @Value("${cache.actor.ttl:900}")
  private int actorCacheSeconds = 900;

  @Value("${cache.bruteForceDeny.ttl:24}")
  private int bruteForceDenyCacheHours = 24;

  @Value("${cache.bruteForceDeny.maxRamEntries:5000}")
  private int bruteForceDenyCacheMaxRamEntries = 5000;

  @Value("${cache.bruteForceDeny.maxDiskMb:100}")
  private int bruteForceDenyCacheMaxDiskMb = 100;

  @Value("${app.cache.persistence.path}")
  private Path persistencePath;

  /**
   * Get the cache manager.
   * 
   * @return the manager.
   */
  @Bean
  public CacheManager appCacheManager() {
    CachingProvider cachingProvider = Caching.getCachingProvider();
    if (cachingProvider instanceof EhcacheCachingProvider) {
      DefaultConfiguration configuration = new DefaultConfiguration(
          cachingProvider.getDefaultClassLoader(),
          new DefaultPersistenceConfiguration(persistencePath.toFile()));
      return ((EhcacheCachingProvider) cachingProvider)
          .getCacheManager(cachingProvider.getDefaultURI(), configuration);
    } else {
      return cachingProvider.getCacheManager();
    }
  }

  /**
   * Get the actor cache.
   * 
   * @return the actor cache
   */
  @Bean
  @Qualifier("actor")
  @Profile("!default")
  public Cache<String, Actor> actorCache(CacheManager cacheManager) {
    return cacheManager.createCache(ACTOR_CACHE_NAME, actorCacheConfiguration());
  }

  // CHECKSTYLE IGNORE LineLength FOR NEXT 1 LINE
  private javax.cache.configuration.Configuration<String, Actor> actorCacheConfiguration() {
    MutableConfiguration<String, Actor> conf = new MutableConfiguration<>();
    conf.setExpiryPolicyFactory(
        CreatedExpiryPolicy.factoryOf(new Duration(TimeUnit.SECONDS, actorCacheSeconds)));
    conf.setStoreByValue(false);
    return conf;
  }

  /**
   * The brute-force mitigation deny list.
   * 
   * @return the cache
   */
  @Bean
  @Qualifier("brute-force-deny-list")
  @Profile("!default")
  public Cache<InetAddress, Byte> bruteForceDenyListCache(CacheManager cacheManager) {
    if (cacheManager == null) {
      return null;
    }
    return cacheManager.createCache("brute-force-deny-list",
        bruteForceDenyListCacheConfiguration());
  }

  // CHECKSTYLE OFF: LineLength
  private javax.cache.configuration.Configuration<InetAddress, Byte> bruteForceDenyListCacheConfiguration() {
    CacheConfiguration<InetAddress, Byte> conf = CacheConfigurationBuilder
        .newCacheConfigurationBuilder(InetAddress.class, Byte.class,
            ResourcePoolsBuilder.heap(bruteForceDenyCacheMaxRamEntries)
                .disk(bruteForceDenyCacheMaxDiskMb, MemoryUnit.MB, true))
        .withExpiry(ExpiryPolicyBuilder
            .timeToLiveExpiration(java.time.Duration.ofHours(bruteForceDenyCacheHours)))
        .build();
    return Eh107Configuration.fromEhcacheCacheConfiguration(conf);
  }
  // CHECKSTYLE ON: LineLength

}
