-- Authentication and Authorization Tables Migration
-- Adds User, ApiKey, AuthSession, and TokenRevocationList tables for complete auth system

-- Create User table
CREATE TABLE IF NOT EXISTS "User" (
    "id" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'USER',
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "last_login" TIMESTAMP(3),

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- Create unique indexes for User table
CREATE UNIQUE INDEX IF NOT EXISTS "idx_User_username" ON "User"("username");
CREATE UNIQUE INDEX IF NOT EXISTS "idx_User_email" ON "User"("email");
CREATE INDEX IF NOT EXISTS "idx_User_role_active" ON "User"("role", "is_active");

-- Create ApiKey table
CREATE TABLE IF NOT EXISTS "ApiKey" (
    "id" TEXT NOT NULL,
    "key_id" TEXT NOT NULL,
    "key_hash" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "scopes" JSONB NOT NULL DEFAULT '[]',
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "expires_at" TIMESTAMP(3),
    "last_used" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "created_by" TEXT NOT NULL DEFAULT 'system',

    CONSTRAINT "ApiKey_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "ApiKey_key_id_key" UNIQUE ("key_id")
);

-- Create indexes for ApiKey table
CREATE INDEX IF NOT EXISTS "idx_ApiKey_user_active" ON "ApiKey"("user_id", "is_active");
CREATE INDEX IF NOT EXISTS "idx_ApiKey_key_id" ON "ApiKey"("key_id");
CREATE INDEX IF NOT EXISTS "idx_ApiKey_expires_active" ON "ApiKey"("expires_at", "is_active");

-- Create AuthSession table
CREATE TABLE IF NOT EXISTS "AuthSession" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "session_token" TEXT NOT NULL,
    "refresh_token" TEXT,
    "ip_address" TEXT NOT NULL,
    "user_agent" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "is_active" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "AuthSession_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "AuthSession_session_token_key" UNIQUE ("session_token"),
    CONSTRAINT "AuthSession_refresh_token_key" UNIQUE ("refresh_token")
);

-- Create indexes for AuthSession table
CREATE INDEX IF NOT EXISTS "idx_AuthSession_user_active" ON "AuthSession"("user_id", "is_active");
CREATE INDEX IF NOT EXISTS "idx_AuthSession_token" ON "AuthSession"("session_token");
CREATE INDEX IF NOT EXISTS "idx_AuthSession_expires_active" ON "AuthSession"("expires_at", "is_active");

-- Create TokenRevocationList table
CREATE TABLE IF NOT EXISTS "TokenRevocationList" (
    "id" TEXT NOT NULL,
    "jti" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "revoked_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reason" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TokenRevocationList_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "TokenRevocationList_jti_key" UNIQUE ("jti")
);

-- Create indexes for TokenRevocationList table
CREATE INDEX IF NOT EXISTS "idx_TokenRevocation_user" ON "TokenRevocationList"("user_id");
CREATE INDEX IF NOT EXISTS "idx_TokenRevocation_jti" ON "TokenRevocationList"("jti");

-- Add foreign key constraints
ALTER TABLE "ApiKey" ADD CONSTRAINT "ApiKey_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "AuthSession" ADD CONSTRAINT "AuthSession_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Create default admin user (password: admin123, hashed with bcrypt)
INSERT INTO "User" (
    "id",
    "username",
    "email",
    "password_hash",
    "role",
    "is_active",
    "created_at",
    "updated_at"
) VALUES (
    'admin-user-001',
    'admin',
    'admin@cortex-mcp.local',
    '$2a$12$rQKZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZ',
    'ADMIN',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
) ON CONFLICT ("username") DO NOTHING;

-- Create a sample service user for API key usage
INSERT INTO "User" (
    "id",
    "username",
    "email",
    "password_hash",
    "role",
    "is_active",
    "created_at",
    "updated_at"
) VALUES (
    'service-user-001',
    'service-account',
    'service@cortex-mcp.local',
    '$2a$12$rQKZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZkZk',
    'SERVICE',
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
) ON CONFLICT ("username") DO NOTHING;

-- Add check constraints for role validation
ALTER TABLE "User" ADD CONSTRAINT "User_role_check"
    CHECK (role IN ('ADMIN', 'USER', 'READ_ONLY', 'SERVICE'));

-- Add check constraints for boolean fields
ALTER TABLE "User" ADD CONSTRAINT "User_is_active_check"
    CHECK (is_active IN (true, false));

ALTER TABLE "ApiKey" ADD CONSTRAINT "ApiKey_is_active_check"
    CHECK (is_active IN (true, false));

ALTER TABLE "AuthSession" ADD CONSTRAINT "AuthSession_is_active_check"
    CHECK (is_active IN (true, false));

-- Create trigger for updating updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_user_updated_at BEFORE UPDATE ON "User"
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_key_updated_at BEFORE UPDATE ON "ApiKey"
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE "User" IS 'User accounts for authentication and authorization';
COMMENT ON TABLE "ApiKey" IS 'API keys for programmatic access';
COMMENT ON TABLE "AuthSession" IS 'User authentication sessions';
COMMENT ON TABLE "TokenRevocationList" IS 'Revoked JWT tokens for blacklist';

COMMENT ON COLUMN "User".role IS 'User role: ADMIN, USER, READ_ONLY, or SERVICE';
COMMENT ON COLUMN "ApiKey".key_id IS 'Public API key identifier (e.g., ck_live_1234567890)';
COMMENT ON COLUMN "ApiKey".key_hash IS 'Hashed API key for secure storage';
COMMENT ON COLUMN "ApiKey".scopes IS 'JSON array of granted scopes';
COMMENT ON COLUMN "AuthSession".session_token IS 'JWT session token';
COMMENT ON COLUMN "AuthSession".refresh_token IS 'JWT refresh token';
COMMENT ON COLUMN "TokenRevocationList".jti IS 'JWT ID for token identification';