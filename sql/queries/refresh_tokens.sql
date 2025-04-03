-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at)
VALUES (
    $1,
    now(),
    now(),
    $2,
    $3
)
RETURNING *;

-- name: DeleteAllRefreshTokens :exec
DELETE FROM refresh_tokens;

-- name: GetAllRefreshTokens :many
SELECT * FROM refresh_tokens
ORDER BY created_at ASC
;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1
and expires_at > now() and revoked_at is null
;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = now(), updated_at = now()
WHERE token = $1
;