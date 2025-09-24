# VEDATRACE
ISIH-2025 AstraX

VEDATRACE is a blockchain herb traceability platform built to trace the lifecycle of Ayurvedic and herbal products — from the farm to the consumer.

---

## Tech Stack

| Layer     | Tech Used                                       |
|-----------|-------------------------------------------------|
| Frontend  | React (with Next.js App Router, TypeScript)     |
| Styling   | Tailwind CSS                                    |
| Backend   | Next.js (API Routes),Typescript(.ts),Prisma ORM |
| Database  | PostgreSQL                                      |
| Auth      | (Planned: JWT or NextAuth)                      |
| Package   | npm                                             |

---

## Getting Started – Local Development Setup

### 1. **Clone the Repository**

```bash
git clone https://github.com/Parshv-sudo/VEDATRACE.git
cd VEDATRACE
```

### 2. Install Dependencies
```
npm install
```
You can see all project dependencies listed in package.json.

### 3. Set Up the Database
➤ Start PostgreSQL locally (make sure it's running on port 5432). Create a database called vedatrace manually OR run:
```
CREATE DATABASE vedatrace;
```
➤ Create a .env file at the root:
```
DATABASE_URL="postgresql://youruser:yourpassword@localhost:5432/vedatrace"
```
If your password includes special characters then URL-encode.
### 4. Prisma Setup
```
npx prisma db pull     # Pull the DB schema
npx prisma generate    # Generate Prisma client
```
Your models will be in prisma/schema.prisma.

### 5. Middleware Setup  
middleware.ts file in the root of project's app directory 

### 6. Run the App Locally
```
npm run dev
```
Your app should now be running at: http://localhost:3000

### Project Structure (Brief Overview)
```
app/                → Pages and routes (Next.js App Router)
├── (routes)/
├── api/
├── middleware.ts   # This file handles the middleware logic
└── layout.tsx
components/         → Reusable UI components
lib/                → Prisma client and helpers
prisma/schema.prisma → DB models
public/             → Static assets
styles/             → Global styles
```
### Contributing
Before You Start
```
-Pull the latest changes from main:
-Create a new branch:
-Make your changes and commit:
-Push and open a Pull Request:
```


