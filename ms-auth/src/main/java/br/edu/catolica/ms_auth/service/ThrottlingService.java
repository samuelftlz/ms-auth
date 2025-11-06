package br.edu.catolica.ms_auth.service;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

@Service
public class ThrottlingService {

    public static final int MAX_REQUESTS_PER_MINUTE = 3;

    private final Cache throttleCache;

    public ThrottlingService(CacheManager cacheManager) {

        this.throttleCache = cacheManager.getCache("throttleCache");
    }

    public boolean isThrottled(String key) {
        Integer attempts = throttleCache.get(key, Integer.class);

        return attempts != null && attempts >= MAX_REQUESTS_PER_MINUTE;
    }

    public void incrementAttempt(String key) {

        Integer attempts = throttleCache.get(key, Integer.class);

        if (attempts == null) {
            attempts = 1;
        } else {
            attempts++;
        }

        throttleCache.put(key, attempts);
    }
}