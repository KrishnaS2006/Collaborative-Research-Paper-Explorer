# Collaborative Research Paper Explorer

A full-stack web application designed to help users explore research papers and support collaborative research workflows.

## 📌 Project Overview

**Collaborative Research Paper Explorer** is being developed with a React frontend and a Node.js/Express backend. The backend uses PostgreSQL for data storage and JWT-based authentication.

This repository is under active development. Features and setup instructions may evolve as the project grows.

## 🛠️ Tech Stack

### Frontend
- React
- Vite
- JavaScript
- Tailwind CSS
- React Router (where configured)

### Backend
- Node.js
- Express.js
- PostgreSQL
- `pg` — PostgreSQL client
- JWT (`jsonwebtoken`) — authentication tokens
- `bcryptjs` — password hashing
- `cookie-parser` — cookie handling
- `cors` — cross-origin request configuration
- `dotenv` — environment variables
- Nodemailer — email delivery for password-reset workflows

### Development and Deployment
- Git and GitHub
- Docker and Docker Compose — containerization setup
- CI/CD — planned automation for testing and deployment

## 📂 Project Structure

```text
Collaborative-Research-Paper-Explorer/
├── backend/
│   ├── src/
│   │   ├── config/
│   │   │   └── env.js
│   │   ├── repositories/
│   │   ├── services/
│   │   ├── controllers/
│   │   ├── routes/
│   │   ├── middleware/
│   │   ├── utils/
│   │   ├── app.js
│   │   └── server.js
│   ├── test/
│   ├── .env
│   ├── package.json
│   └── package-lock.json
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── package-lock.json
│
├── compose.yaml
├── .gitignore
└── README.md
```

*Note: The directory tree represents the intended structure. Adjust it to match the files currently present in your repository.*

## ✨ Backend Features and Work in Progress

- Express application with centralized middleware and error handling.
- PostgreSQL database connectivity.
- User registration and login workflows.
- Password hashing using bcrypt.
- JWT-based authentication.
- Cookie-based authentication support.
- Password-reset token generation and expiration.
- Password-reset email integration using Nodemailer.
- Environment-based configuration.
- Automated tests using Node.js's built-in test runner.
- Docker-based development setup.

## ⚙️ Prerequisites

Install the following tools before starting:

- [Node.js](https://nodejs.org/) — Node.js 22 is the current project development version.
- npm — included with Node.js.
- [Git](https://git-scm.com/)
- PostgreSQL database or a compatible hosted PostgreSQL database, such as Neon.
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) — required only for Docker-based development.

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Collaborative-Research-Paper-Explorer
```

Replace the placeholder with the actual GitHub repository URL.

### 2. Install backend dependencies

```bash
cd backend
npm install
```

### 3. Configure environment variables

Create a `backend/.env` file:

```dotenv
NODE_ENV=development
PORT=5000

DATABASE_URL=YOUR_POSTGRESQL_CONNECTION_STRING
JWT_SECRET=YOUR_RANDOM_SECRET_AT_LEAST_32_CHARACTERS_LONG

FRONTEND_URL=http://localhost:5173

EMAIL_SERVICE_MODE=console

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
```

Replace the database connection string and JWT secret with your own values.

**Security guidelines:**
- Never commit `.env` files to GitHub.
- Never share database passwords, SMTP credentials, or JWT secrets publicly.
- Use a strong, randomly generated JWT secret.
- For real password-reset email delivery, configure SMTP credentials and the email settings supported by the implementation.
- `EMAIL_SERVICE_MODE=console` should be used only if the current email service supports console mode.

### 4. Start the backend

From the `backend` directory:

```bash
npm run dev
```

The backend is configured to use port `5000` by default.

Check the health endpoint:

```text
http://localhost:5000/health
```

### 5. Start the frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Vite normally starts the frontend at:

```text
http://localhost:5173
```

If the frontend uses the Vite development proxy, API requests should use relative paths such as `/api/auth/login`. Confirm that the proxy target matches how the backend is running.

## 🧪 Running Tests

From the backend directory:

```bash
npm test
```

The backend test script uses Node.js's built-in test runner. Ensure your test files are located under `backend/test/` and use supported test file naming.

## 🐳 Docker Development

Docker allows the frontend and backend to run in separate containers, making it easier for team members to use a consistent development environment.

The intended architecture is:

```text
Browser
   |
   v
Frontend — Vite :5173
   |
   | /api requests through Vite proxy
   v
Backend — Express :5000
   |
   v
PostgreSQL / Neon
```

### Start the containers

Once the Dockerfiles and root `compose.yaml` are configured:

```bash
docker compose up --build
```

Run the services in the background:

```bash
docker compose up --build -d
```

View logs:

```bash
docker compose logs -f
```

View running containers:

```bash
docker compose ps
```

Stop the containers:

```bash
docker compose down
```

The frontend Vite proxy must target the backend's Docker Compose service name when Vite runs inside Docker. For example, if the service is named `backend`, the target is `http://backend:5000`.

The backend must listen on `0.0.0.0` inside its container so Docker can route traffic to it.

**Important:** Docker commands require the Docker configuration files to be created and verified first. The commands above describe the intended workflow.

## 🔐 Authentication and Password Reset

The backend's authentication workflow is designed around:

1. Registering a user.
2. Hashing passwords before storage.
3. Logging in and issuing a JWT.
4. Supporting authentication through cookies.
5. Requesting a password reset.
6. Generating a time-limited reset token.
7. Validating the token before updating the password.
8. Sending password-reset emails through the configured email service.

Reset tokens should be handled securely and must expire. Do not log or expose production credentials or sensitive tokens.

## 🌿 Git Workflow for Team Collaboration

For collaborative development, use feature branches rather than committing every change directly to the shared development branch.

### Create a feature branch

```bash
git switch developer
git pull origin developer
git switch -c feature/your-feature-name
```

### Save your changes

```bash
git add .
git commit -m "feat: describe your change"
git push -u origin feature/your-feature-name
```

Open a Pull Request to merge the feature branch into `developer` after reviewing the changes and running the relevant tests.

### Useful Git commands

```bash
git status
git branch
git branch -a
git pull origin developer
git log --oneline --graph --all
```

Before merging remote changes, check `git status` and resolve any existing merge or stash conflicts carefully. Do not discard stashes or reset changes unless you are certain they are no longer needed.

## 🔄 CI/CD Roadmap

The planned CI/CD workflow can automate quality checks whenever a developer pushes code or opens a Pull Request.

Potential pipeline stages:

1. Check out the repository.
2. Set up the required Node.js version.
3. Install dependencies using the lockfiles.
4. Run backend tests.
5. Build the frontend.
6. Build Docker images.
7. Deploy after the required checks pass.

CI/CD configuration should be added after confirming that the current tests, frontend build, and Docker setup work correctly.

## 🔒 Security

- Keep `.env` files out of version control.
- Store production secrets in the deployment platform's secret manager.
- Validate incoming request data.
- Hash passwords instead of storing plaintext passwords.
- Configure CORS and cookie settings for the intended environment.
- Use HTTPS in production.
- Add appropriate rate limits to authentication and password-reset endpoints.
- Avoid returning internal errors or sensitive database details to clients.

## 🗺️ Development Roadmap

- [x] Initial backend package configuration
- [x] Environment configuration foundation
- [x] Express application and server structure
- [x] PostgreSQL integration foundation
- [x] Authentication and password-reset service work
- [ ] Verify all authentication and password-reset tests
- [ ] Complete and verify frontend/backend integration
- [ ] Finalize Dockerfiles and Docker Compose
- [ ] Set up automated CI/CD checks
- [ ] Configure production deployment
- [ ] Document confirmed API endpoints and usage examples

The checklist should be updated as each item is verified in the repository.

## 👥 Contributing

1. Create a feature branch.
2. Keep changes focused and avoid committing secrets.
3. Run the relevant tests before opening a Pull Request.
4. Describe the change and any configuration requirements.
5. Request a review before merging into the shared development branch.

## 📄 License

The project currently uses the license metadata declared in `backend/package.json`. Add a root-level `LICENSE` file and update this section once the project license has been decided.
