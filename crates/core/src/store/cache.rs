use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::{AuthError, AuthResult};

/// Standalone cache operations; the auth runtime does not install a cache automatically.
#[async_trait]
pub trait CacheAdapter: Send + Sync {
    /// Set a value with expiration
    async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()>;

    /// Get a value by key
    async fn get(&self, key: &str) -> AuthResult<Option<String>>;

    /// Delete a value by key
    async fn delete(&self, key: &str) -> AuthResult<()>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> AuthResult<bool>;

    /// Set expiration for a key
    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()>;

    /// Clear all cached values
    async fn clear(&self) -> AuthResult<()>;
}

/// In-memory cache adapter for testing and development
pub struct MemoryCacheAdapter {
    data: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: String,
    expires_at: DateTime<Utc>,
}

impl MemoryCacheAdapter {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Clean up expired entries
    fn cleanup_expired(&self) {
        if let Ok(mut data) = self.data.lock() {
            let now = crate::time::now();
            data.retain(|_, entry| entry.expires_at > now);
        }
    }
}

impl Default for MemoryCacheAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheAdapter for MemoryCacheAdapter {
    async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()> {
        self.cleanup_expired();

        let expires_at = crate::time::now() + expires_in;
        let entry = CacheEntry {
            value: value.to_string(),
            expires_at,
        };

        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let _ = data.insert(key.to_string(), entry);

        Ok(())
    }

    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        self.cleanup_expired();

        let data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let now = crate::time::now();

        if let Some(entry) = data.get(key) {
            if entry.expires_at > now {
                Ok(Some(entry.value.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let _ = data.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.cleanup_expired();

        let data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        let now = crate::time::now();

        if let Some(entry) = data.get(key) {
            Ok(entry.expires_at > now)
        } else {
            Ok(false)
        }
    }

    async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;

        if let Some(entry) = data.get_mut(key) {
            entry.expires_at = crate::time::now() + expires_in;
        }

        Ok(())
    }

    async fn clear(&self) -> AuthResult<()> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| AuthError::internal("Cache lock poisoned"))?;
        data.clear();
        Ok(())
    }
}

#[cfg(feature = "redis-cache")]
pub mod redis_adapter {
    use super::*;
    use crate::error::AuthError;
    use redis::{AsyncCommands, Client, aio::ConnectionManager};

    /// Standalone Redis cache. Authentication sessions do not use this adapter automatically.
    #[derive(Clone)]
    pub struct RedisAdapter {
        connection: ConnectionManager,
    }

    impl RedisAdapter {
        /// Connect to Redis using Tokio without blocking the executor.
        pub async fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
            let connection = Client::open(redis_url)?.get_connection_manager().await?;
            Ok(Self { connection })
        }
    }

    #[async_trait]
    impl CacheAdapter for RedisAdapter {
        async fn set(&self, key: &str, value: &str, expires_in: Duration) -> AuthResult<()> {
            let seconds = u64::try_from(expires_in.num_seconds())
                .map_err(|_| AuthError::validation("Redis set_ex requires non-negative TTL"))?;
            let mut connection = self.connection.clone();
            connection.set_ex::<_, _, ()>(key, value, seconds).await?;
            Ok(())
        }

        async fn get(&self, key: &str) -> AuthResult<Option<String>> {
            Ok(self.connection.clone().get(key).await?)
        }

        async fn delete(&self, key: &str) -> AuthResult<()> {
            let _: usize = self.connection.clone().del(key).await?;
            Ok(())
        }

        async fn exists(&self, key: &str) -> AuthResult<bool> {
            Ok(self.connection.clone().exists(key).await?)
        }

        async fn expire(&self, key: &str, expires_in: Duration) -> AuthResult<()> {
            let _: bool = self
                .connection
                .clone()
                .expire(key, expires_in.num_seconds())
                .await?;
            Ok(())
        }

        /// Remove every key from the selected Redis database.
        async fn clear(&self) -> AuthResult<()> {
            redis::cmd("FLUSHDB")
                .query_async::<()>(&mut self.connection.clone())
                .await?;
            Ok(())
        }
    }
}

#[cfg(feature = "redis-cache")]
pub use redis_adapter::RedisAdapter;
