package br.edu.catolica.ms_auth.service;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

@Service
public class LoginAttemptService {

    public static final int MAX_ATTEMPTS = 3;

    private final Cache loginAttemptCache;


    public LoginAttemptService(CacheManager cacheManager) {
        this.loginAttemptCache = cacheManager.getCache("loginAttempts");
    }

    public void loginSucceeded(String key) {
        loginAttemptCache.evict(key);
    }

    public void loginFailed(String key) {
        Integer attempts = loginAttemptCache.get(key, Integer.class);

        if (attempts == null) {

            attempts = 1;
        } else {
            attempts++;
        }

        loginAttemptCache.put(key, attempts);
    }

    public boolean isBlocked(String key) {

        Integer attempts = loginAttemptCache.get(key, Integer.class);

        return attempts != null && attempts >= MAX_ATTEMPTS;
    }
}