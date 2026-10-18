
# Collaborative Research Paper Explorer

A collaborative platform designed to help researchers and students discover, explore, organize, and share research papers in one place.

## Overview

The Collaborative Research Paper Explorer aims to simplify the research workflow by bringing paper discovery and collaborative research management into a single web application. Users can explore research papers, manage their research interests, and work with other researchers through a centralized platform.

## Features

- **User Authentication** — Secure registration and login.
- **Research Paper Discovery** — Explore relevant research papers.
- **Research Interests** — Manage personal research interests.
- **Collaborative Research** — Support collaboration and sharing of research resources.
- **Role-Based Access Control** — Different access levels for administrators, lab annotators, and viewers.
- **Database Management** — Store and manage application data using PostgreSQL.
- **Responsive Interface** — Access the application through a web-based interface.

> Note: Update this section to reflect the features currently implemented in the repository.

## Tech Stack

| Component | Technology |
|---|---|
| Frontend | JavaScript-based web application |
| Backend | Node.js |
| Database | PostgreSQL |
| Authentication | JWT (JSON Web Tokens) |
| Version Control | Git and GitHub |

Check the frontend and backend `package.json` files for the exact frameworks and dependencies.

## Project Structure

```text
Collaborative-Research-Paper-Explorer/
├── backend/
│   ├── src/
│   │   ├── config/
│   │   └── ...
│   ├── package.json
│   └── ...
├── frontend/
│   ├── src/
│   ├── package.json
│   └── ...
├── database/
│   └── schema.sql
├── .gitignore
└── README.md
```

*The tree above is illustrative. Adjust it to match the actual repository.*

## Prerequisites

Install the following before running the project:

- [Node.js](https://nodejs.org/)
- npm (included with Node.js)
- [PostgreSQL](https://www.postgresql.org/)
- Git

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/omp091220-git/Collaborative-Research-Paper-Explorer.git
cd Collaborative-Research-Paper-Explorer
```

### 2. Configure the Database

Make sure PostgreSQL is running.

Create the project database if it does not already exist:

```sql
CREATE DATABASE research_explorer;
```

Connect to the database:

```bash
psql -U postgres -h localhost -d research_explorer
```

If the project provides a database schema, execute it using the instructions in the repository. For example, from the project root:

```bash
psql -U postgres -h localhost -d research_explorer -f database/schema.sql
```

Use the PostgreSQL username and password configured on your machine.

### 3. Configure Environment Variables

Create a `.env` file in the backend directory if that is where the backend loads its environment configuration.

Example:

```env
PORT=5000
JWT_SECRET=replace_with_a_long_random_secret
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/research_explorer
```

Replace `YOUR_PASSWORD` with your local PostgreSQL password.

**Important:**
- Check `backend/src/config/env.js` to confirm the required variable names and database configuration format.
- Generate a strong, unique JWT secret.
- Never commit `.env` files, passwords, or real secrets to GitHub.
- Add an `.env.example` file containing placeholders for the variables teammates need.

### 4. Install Backend Dependencies

Open a terminal in the repository root:

```bash
cd backend
npm install
```

Start the backend using the available script:

```bash
npm start
```

If the project provides a development script, you can use:

```bash
npm run dev
```

### 5. Install Frontend Dependencies

Open a second terminal:

```bash
cd frontend
npm install
```

Start the frontend:

```bash
npm run dev
```

If the frontend uses a different start script, check its `package.json`.

### 6. Open the Application

Open the local URL displayed in the frontend terminal, commonly:

```text
http://localhost:5173
```

The backend URL and port depend on the project's configuration.

## Troubleshooting

### Missing `JWT_SECRET`

Make sure the backend environment file contains the required `JWT_SECRET` variable and restart the backend.

### PostgreSQL Authentication Failed

- Verify that PostgreSQL is running.
- Check the database username and password.
- Confirm that the `research_explorer` database exists.
- Verify the connection settings in the backend environment configuration.

### npm Scripts Not Working on Windows

In PowerShell, try:

```powershell
npm.cmd install
npm.cmd start
```

For development:

```powershell
npm.cmd run dev
```

Use the scripts supported by each directory's `package.json`.

### Frontend Cannot Connect to Backend

Check the backend port, frontend API base URL, CORS configuration, and whether the backend server is running.

## Development Workflow

To contribute to the project:

1. Pull the latest changes from the shared repository.
2. Create a separate feature branch.
3. Implement and test your changes.
4. Commit and push your branch.
5. Open a pull request for review before merging into `main`.

Example:

```bash
git checkout main
git pull origin main
git checkout -b feature/your-feature
git add .
git commit -m "Add your feature"
git push -u origin feature/your-feature
```

## Contributing

Contributions from team members are welcome. Please use feature branches and pull requests so changes can be reviewed before they are merged into the main branch.

## Security

- Never commit API keys, database passwords, or JWT secrets.
- Validate user input on the backend.
- Use appropriate authorization checks for protected resources.
- Keep dependencies updated.

## License

Add the project's chosen license here before distributing the software.
