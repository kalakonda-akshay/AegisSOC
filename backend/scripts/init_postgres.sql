-- =============================================================================
-- AegisSOC PostgreSQL Initialization Script
-- Mounts into /docker-entrypoint-initdb.d/ to initialize extensions and schema
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant schema permissions
GRANT ALL PRIVILEGES ON DATABASE aegissoc TO postgres;
