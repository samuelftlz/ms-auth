package br.edu.catolica.ms_auth.config;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableCaching
public class CacheConfig {


    private static final long TTL_LOGIN_ATTEMPTS_MINUTES = 10;
    private static final long TTL_THROTTLE_MINUTES = 1;
    private static final long TTL_PASSWORD_RESET_MINUTES = 10;

    @Bean
    public RedisCacheManager cacheManager(RedisConnectionFactory connectionFactory) {

        RedisCacheConfiguration defaultConfig = RedisCacheConfiguration.defaultCacheConfig()
                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(new GenericJackson2JsonRedisSerializer()));

        RedisCacheConfiguration loginAttemptsConfig = defaultConfig
                .entryTtl(Duration.ofMinutes(TTL_LOGIN_ATTEMPTS_MINUTES));

        RedisCacheConfiguration throttleConfig = defaultConfig
                .entryTtl(Duration.ofMinutes(TTL_THROTTLE_MINUTES));

        RedisCacheConfiguration passwordResetConfig = defaultConfig
                .entryTtl(Duration.ofMinutes(TTL_PASSWORD_RESET_MINUTES));

        Map<String, RedisCacheConfiguration> cacheConfigurations = new HashMap<>();

        cacheConfigurations.put("loginAttempts", loginAttemptsConfig);
        cacheConfigurations.put("throttleCache", throttleConfig);
        cacheConfigurations.put("passwordResetCache", passwordResetConfig);

        return RedisCacheManager.builder(connectionFactory)
                .withInitialCacheConfigurations(cacheConfigurations)
                .build();
    }
}