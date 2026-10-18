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
