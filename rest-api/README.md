# REST API Server

The Asfaload REST API server handles artifact signing workflows and provides endpoints for managing signatures, signing requests, and git repository operations.

## Starting the Server

### Development Mode

```bash
# Set required environment variable
export ASFASIGN_GIT_REPO_PATH=/path/to/git/repo

# Start server in debug mode
cargo run --package rest-api

# Start server in release mode (faster)
cargo run --release --package rest-api
```

### Production Mode

```bash
# Set environment variables
export ASFASIGN_GIT_REPO_PATH=/path/to/git/repo
export ASFASIGN_SERVER_PORT=8080
export ASFASIGN_LOG_LEVEL=info

# Build and start
cargo build --release --package rest-api
./target/release/rest-api
```

### Using Makefile (for Testing)

The Makefile provides convenience targets for testing:

```bash
# Run client-server integration tests
make client-server-tests

# Show all available commands
make help
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ASFASIGN_GIT_REPO_PATH` | ✅ Yes | *none* | Path to git repository for storing signed artifacts |
| `ASFASIGN_SERVER_PORT` | ❌ No | `3000` | Port for the server to listen on |
| `ASFASIGN_LOG_LEVEL` | ❌ No | `info` | Logging level: `debug`, `info`, `warn`, or `error` |
| `ASFASIGN_GITHUB_API_KEY` | ❌ No | *none* | GitHub API token for fetching signers files |
| `ASFASIGN_GITLAB_API_KEY` | ❌ No | *none* | GitLab API token for fetching signers files |

## Quick Start Examples

### Local Development

```bash
# Create a git repository
mkdir -p /tmp/asfaload-repo
git -C /tmp/asfaload-repo init
git -C /tmp/asfaload-repo config user.name "Dev User"
git -C /tmp/asfaload-repo config user.email "dev@example.com"

# Start server
export ASFASIGN_GIT_REPO_PATH=/tmp/asfaload-repo
export ASFASIGN_SERVER_PORT=3000
export ASFASIGN_LOG_LEVEL=debug
cargo run --package rest-api
```

### Docker Deployment

```bash
# Build image
docker build -t asfaload/rest-api .

# Run container
docker run -d \
  -p 3000:3000 \
  -e ASFASIGN_GIT_REPO_PATH=/data/repo \
  -e ASFASIGN_LOG_LEVEL=info \
  -v /path/to/repo:/data/repo \
  asfaload/rest-api
```

## API Endpoints

The server provides RESTful endpoints for:

- `POST /add-file` - Add a file to be signed
- `GET /pending-signatures` - List files pending signatures
- `POST /submit-signature` - Submit a signature for a file
- `POST /register-repo` - Register a repository for signature collection

See the API documentation for detailed endpoint specifications.

## Development

### Build

```bash
# Debug build
cargo build --package rest-api

# Release build
cargo build --release --package rest-api
```

### Run Tests

```bash
# All tests
make test

# With integration tests
make test-with-test-utils

# Client-server integration tests
make client-server-tests
```

### Lint

```bash
# Run clippy
make clippy

# Format code
make format

# Check formatting
make check-format
```

## Architecture

The server uses an actor-based architecture with:

- **GitActor**: Handles git operations and commits
- **NonceCacheActor**: Manages nonce storage for request authentication
- **NonceCleanupActor**: Cleans up expired nonces
- **ForgeProjectAuthenticator**: Validates signers from GitHub/GitLab
- **SignersInitialiser**: Initializes signers configuration
- **SignatureCollector**: Collects and aggregates signatures
- **ReleaseActor**: Manages final signature release

## Security

- All API requests require authentication using Ed25519 signatures
- Nonces prevent replay attacks
- Request timestamps are validated
- Git repository is secured with proper file permissions
- API keys for GitHub/GitLab are optional and stored in environment

## Troubleshooting

### "Address already in use" error

Port 3000 (or your specified port) is already in use:

```bash
# Check what's on the port
lsof -i :3000

# Kill the process
kill <PID>

# Or use a different port
export ASFASIGN_SERVER_PORT=8080
```

### "git_repo_path cannot be empty" error

Required environment variable not set:

```bash
export ASFASIGN_GIT_REPO_PATH=/path/to/repo
```

### Server not starting

Check the git repository is valid:

```bash
# Initialize if needed
git -C /path/to/repo init
git -C /path/to/repo config user.name "Server User"
git -C /path/to/repo config user.email "server@example.com"
```

## License

See project LICENSE file for details.
