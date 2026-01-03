-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
    uuidv4(),
    NOW(),
    NOW(),
    $1
)
RETURNING *;
