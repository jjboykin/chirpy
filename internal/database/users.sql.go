// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: users.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

type CreateUserParams struct {
	Email          string
	HashedPassword string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.Email, arg.HashedPassword)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const deleteAllUsers = `-- name: DeleteAllUsers :exec
DELETE FROM users
`

func (q *Queries) DeleteAllUsers(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllUsers)
	return err
}

const getUser = `-- name: GetUser :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users
WHERE email = $1
`

func (q *Queries) GetUser(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUser, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const updateUserAuth = `-- name: UpdateUserAuth :one
UPDATE users 
SET updated_at = now(), email = $2, hashed_password = $3
WHERE id = $1
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

type UpdateUserAuthParams struct {
	ID             uuid.UUID
	Email          string
	HashedPassword string
}

func (q *Queries) UpdateUserAuth(ctx context.Context, arg UpdateUserAuthParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUserAuth, arg.ID, arg.Email, arg.HashedPassword)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const updateUserChirpyRed = `-- name: UpdateUserChirpyRed :one
UPDATE users 
SET updated_at = now(), is_chirpy_red = true
WHERE id = $1
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

func (q *Queries) UpdateUserChirpyRed(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUserChirpyRed, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}
