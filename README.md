# Chirpy

A Twitter-like social media REST API built with Go and PostgreSQL. Chirpy allows users to create accounts, post short messages (chirps), and upgrade to premium membership.

## Features

- User authentication with JWT tokens
- Refresh token-based session management
- Create, read, and delete chirps
- Premium membership system (Chirpy Red)
- Profanity filtering
- Author filtering and sorting
- Secure password hashing with Argon2id

## API Endpoints

### Health & Metrics
- `GET /api/healthz` - Health check
- `GET /admin/metrics` - View server metrics
- `POST /admin/reset` - Reset database (dev environment only)

### User Management
- `POST /api/users` - Create a new user account
- `PUT /api/users` - Update user email/password (requires authentication)
- `POST /api/login` - Login and receive JWT + refresh token
- `POST /api/refresh` - Get a new JWT using refresh token
- `POST /api/revoke` - Revoke refresh token (logout)

### Chirps
- `POST /api/chirps` - Create a new chirp (requires authentication)
- `GET /api/chirps` - Get all chirps
  - Query params: `author_id` (filter by user), `sort=asc|desc` (default: asc)
- `GET /api/chirps/{chirpID}` - Get a specific chirp
- `DELETE /api/chirps/{chirpID}` - Delete a chirp (requires ownership)

### Premium Features
- `POST /api/polka/webhooks` - Webhook for upgrading users to Chirpy Red

## Tech Stack

- **Language:** Go 1.25.5
- **Database:** PostgreSQL
- **Authentication:** JWT (HS256) + Refresh Tokens
- **Password Hashing:** Argon2id
- **SQL Code Generation:** sqlc v1.30.0
- **Migrations:** goose

### Dependencies

- `github.com/alexedwards/argon2id` - Secure password hashing
- `github.com/golang-jwt/jwt/v5` - JWT token handling
- `github.com/google/uuid` - UUID generation
- `github.com/joho/godotenv` - Environment variable management
- `github.com/lib/pq` - PostgreSQL driver

## Getting Started

### Prerequisites

- Go 1.25.5 or higher
- PostgreSQL
- goose (for migrations)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/jabreu610/chirpy.git
cd chirpy
```

2. Install dependencies:
```bash
go mod download
```

3. Create a PostgreSQL database:
```bash
createdb chirpy
```

4. Set up environment variables by creating a `.env` file:
```env
DB_URL="postgres://username:password@localhost:5432/chirpy?sslmode=disable"
PLATFORM="dev"
JWT_SECRET="your-base64-encoded-secret"
POLKA_KEY="your-polka-api-key"
```

5. Run database migrations:
```bash
goose -dir sql/schema postgres "$DB_URL" up
```

6. Build and run the application:
```bash
go build -o chirpy
./chirpy
```

The server will start on `http://localhost:8080`

## Database Schema

### Users
- `id` - UUID (primary key)
- `email` - Unique email address
- `hashed_password` - Argon2id hashed password
- `is_chirpy_red` - Premium membership status
- `created_at`, `updated_at` - Timestamps

### Chirps
- `id` - UUID (primary key)
- `body` - Chirp message text
- `user_id` - Foreign key to users
- `created_at`, `updated_at` - Timestamps

### Refresh Tokens
- `token` - 64-character hex string (primary key)
- `user_id` - Foreign key to users
- `expires_at` - Expiration timestamp (60 days)
- `revoked_at` - Optional revocation timestamp
- `created_at`, `updated_at` - Timestamps

## Authentication

### JWT Tokens
- **Algorithm:** HS256
- **Expiration:** 1 hour
- **Header:** `Authorization: Bearer <token>`

### Refresh Tokens
- **Expiration:** 60 days
- **Usage:** Exchange for new JWT via `/api/refresh`
- **Revocation:** Supported via `/api/revoke`

### Password Security
Passwords are hashed using Argon2id, a memory-hard hashing algorithm recommended for secure password storage.

## Development

### Running Tests
```bash
go test ./...
```

### Regenerating Database Code
After modifying SQL queries in `sql/queries/`:
```bash
sqlc generate
```

### Creating Migrations
Add new migration files in `sql/schema/` with sequential numbering:
```sql
-- sql/schema/006_new_feature.sql
-- +goose Up
CREATE TABLE ...

-- +goose Down
DROP TABLE ...
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_URL` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/chirpy` |
| `PLATFORM` | Environment type (dev/production) | `dev` |
| `JWT_SECRET` | Secret key for JWT signing | Base64-encoded string |
| `POLKA_KEY` | API key for Polka webhooks | API key string |

## Project Structure

```
chirpy/
├── main.go                 # Application entry point
├── internal/
│   ├── auth/              # Authentication logic
│   └── database/          # Generated database code (sqlc)
├── sql/
│   ├── schema/            # Database migrations
│   └── queries/           # SQL query definitions
├── .env                   # Environment configuration
├── go.mod                 # Go dependencies
└── sqlc.yaml             # sqlc configuration
```

## License

This project is part of the Boot.dev curriculum.
