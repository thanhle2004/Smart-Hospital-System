# 🏥 An Integrated Framework for Hospital Management and Healthcare Service Optimization

A full-stack smart hospital operations platform designed to optimize patient flow, reduce waiting time, and improve service allocation efficiency across clinical workflows.

---

## 1. Project Overview

Modern hospitals often face bottlenecks caused by uneven room utilization, manual queue management, and limited visibility into live operations. This project addresses those issues by introducing a structured, data-driven patient flow engine with real-time room queue updates.

The system supports three primary user groups:

- **Patients**: identify themselves, select services, check in, and track visit progress.
- **Doctors**: check in/out of rooms, manage queue execution, and handle patient steps.
- **Administrators**: configure flow templates, room types, patient types, priority rules, users, and monitor operational dashboards.

This framework is built for environments where throughput, fairness, and response time directly affect care quality.

### Why This Matters

In high-volume hospitals, inefficient patient routing can lead to:
- Long waiting times
- Uneven doctor workload
- Poor patient experience

This system introduces a data-driven orchestration layer that:
- Dynamically distributes patient load
- Prioritizes critical cases
- Improves overall healthcare service efficiency

---

## 2. Key Features

### Core Optimization Features

- **Template-based patient flow orchestration**
  - Define reusable service flows (`Flow`, `FlowRoom`, dependencies).
  - Instantiate runtime visit flows (`VisitFlow`) per patient check-in.

- **Priority-driven central queueing**
  - Priority rules based on age range, patient type, and emergency conditions.
  - Support for calculated and manual priority fields in central queue.

- **Dynamic room allocation**
  - Selects next room by minimizing estimated waiting time:
    - queue load
    - room capacity (active doctors)
    - average process time

- **Runtime visit control**
  - Call patient (`WAITING` → `IN_PROGRESS`)
  - Complete step (auto-route to next eligible room)
  - Skip step with dependency-aware safety

### Security & Access Features

- **JWT authentication with refresh token rotation**
  - Access/refresh token flow with hashed refresh tokens stored in DB.
  - Cookie-based and bearer-token compatible guard strategy.

- **Role-based authorization (RBAC)**
  - `ADMIN` and `DOCTOR` roles enforced via guards/decorators on protected endpoints.

- **Patient session protection**
  - HMAC-based patient session token (`patient_session`) for patient self-service APIs.

- **Visit-scoped secure access**
  - HMAC-based `visit_access_token` cookie restricts visit detail visibility.

### Real-time Features

- **Socket.IO room streams**
  - Room queue updates (`room:{id}:queue-updated`)
  - Active doctor/capacity updates (`room:{id}:doctors-updated`)

### Platform Features

- **Swagger/OpenAPI docs** at `/docs`
- **Modular monorepo architecture** (backend, frontend, shared packages)
- **Zod-based DTO validation** in backend controllers

---

## 3. System Workflow

### End-to-end Flow

1. **Patient Identification**
   - Patient registers/checks phone and receives a patient session cookie.
2. **Service Selection**
   - Patient selects a flow (service bundle) defined by admin.
3. **Visit Check-in**
   - System creates a `Visit`, copies flow template into `VisitFlow`, computes priority, inserts to central queue.
4. **Queue & Room Assignment**
   - Engine selects best next room based on queue pressure and room capacity.
5. **Doctor Execution**
   - Doctor calls patient, starts service, completes/skip steps.
6. **Completion**
   - Visit is completed when all required steps are done/skipped.

### How Waiting Time is Reduced

The platform reduces waiting time through multiple mechanisms:

- **Priority triaging**: urgent/high-priority patients can be fast-tracked by rules.
- **Capacity-aware scheduling**: room capacity equals count of active doctors.
- **Queue-aware room selection**: estimated waiting time uses queue length and processing rates.
- **Dependency-constrained progression**: prevents invalid sequencing while keeping flow moving.
- **Real-time queue synchronization**: UI updates immediately after doctor actions.

---

## 4. Tech Stack

| Category | Technology |
|---|---|
| Monorepo | Turbo, pnpm workspaces |
| Backend API | NestJS (TypeScript) |
| ORM | Prisma ORM |
| Database | MySQL |
| Realtime | Socket.IO (NestJS WebSocket Gateway + socket.io-client) |
| Authentication | JWT (access + refresh), cookies, Passport JWT |  
| Validation | Zod (custom NestJS validation pipe) |
| API Docs | Swagger (`/docs`) |
| Frontend | Next.js (App Router), React |
| UI | Tailwind CSS, shadcn/ui, Radix primitives |
| Tooling | ESLint, Prettier, TypeScript |

---

## 5. Architecture & Design Decisions

This system is built around several core architectural decisions to ensure scalability, flexibility, and real-time responsiveness:

- **Central Queue Model**  
  Instead of per-room queues, a global queue enables better optimization.

- **Template → Runtime Flow Pattern**  
  Flow templates are cloned into runtime VisitFlow for flexibility and safety.

- **HMAC-based Patient Tokens**  
  Avoids full authentication while still securing patient operations.

- **Socket-driven UI**  
  Eliminates polling and ensures real-time synchronization.

---

## 6. Project Structure

```text
.
├─ backend/
│  ├─ prisma/
│  │  ├─ schema.prisma
│  │  └─ migrations/
│  └─ src/
│     ├─ main.ts
│     ├─ app.module.ts
│     ├─ config/
│     │  └─ env.ts
│     ├─ common/pipes/
│     │  └─ zod-validation.pipe.ts
│     ├─ shared/
│     │  ├─ prisma/
│     │  └─ services/
│     └─ modules/
│        ├─ auth/         # login/register/refresh/logout/me, JWT, RBAC
│        ├─ patient/      # patient CRUD + patient-session handling
│        ├─ visit/        # check-in, central queue, call/skip/complete lifecycle
│        ├─ visit-flow/   # runtime step management and dependency controls
│        ├─ room/         # room ops, capacity, queue metrics, websocket gateway
│        ├─ flow/         # flow template + dependencies (admin/public)
│        ├─ priority/     # triage rules
│        ├─ patient-type/ # patient classification management
│        ├─ room-type/    # service room categories
│        ├─ user/         # system users (admin/doctor)
│        └─ profile/
├─ frontend/
│  └─ src/
│     ├─ app/
│     │  ├─ (auth)/login, (auth)/register
│     │  ├─ admin/        # admin dashboard and configuration pages
│     │  ├─ doctor/       # doctor dashboard, room queue, display
│     │  └─ patient/      # patient identify/profile/service/result/dashboard
│     ├─ features/
│     │  ├─ auth/
│     │  ├─ admin/
│     │  ├─ doctor/
│     │  └─ patient/
│     └─ proxy.ts         # route protection + role-aware redirects + token refresh
├─ packages/
│  └─ types/
├─ docker-compose.yml
├─ turbo.json
└─ pnpm-workspace.yaml
```

---

## 7. Installation & Setup

### Prerequisites

- **Node.js** 20+
- **pnpm** 10+
- **MySQL** 8+ (or compatible)

### A. Clone & Install Workspace Dependencies

```bash
git clone https://github.com/thanhle2004/Smart-Hospital-System
cd Smart-Hospital-System
pnpm install
```

### B. Backend Setup (NestJS)

```bash
cd backend
pnpm install
```

Create `backend/.env` using the example in the Environment Variables section.

Then initialize Prisma and run backend:

```bash
pnpm prisma generate
pnpm prisma db push
pnpm run start:dev
```

Backend default URL: `http://localhost:5000`  
Swagger docs: `http://localhost:5000/docs`

### C. Frontend Setup (Next.js)

```bash
cd frontend
pnpm install
```

Create `frontend/.env.local` using the example below, then run:

```bash
pnpm dev
```

Frontend default URL: `http://localhost:3000`

### D. Run Full Monorepo (Optional)

From repository root:

```bash
pnpm dev
```

This uses Turbo to run workspace dev scripts in parallel.

---

## 8. Environment Variables

### Backend (`backend/.env`)

```env
# Runtime
NODE_ENV=development
PORT=5000
FRONTEND_URL=http://localhost:3000

# Database (MySQL for current Prisma schema)
DATABASE_URL="mysql://root:123456@localhost:3306/smart_hospital"

# JWT (minimum 32 chars for secrets)
JWT_ACCESS_SECRET=change_this_to_a_long_random_secret_at_least_32_chars
JWT_REFRESH_SECRET=change_this_to_a_long_random_secret_at_least_32_chars
ACCESS_TOKEN_EXPIRES_IN=15m
REFRESH_TOKEN_EXPIRES_IN=7d

# Cookie names
COOKIE_ACCESS=access_token
COOKIE_REFRESH=refresh_token

# Optional patient/visit scoped token secrets
PATIENT_SESSION_SECRET=change_this_patient_session_secret
VISIT_ACCESS_SECRET=change_this_visit_access_secret

# Optional cookie TTL overrides (milliseconds)
PATIENT_SESSION_COOKIE_MAX_AGE_MS=86400000
VISIT_ACCESS_COOKIE_MAX_AGE_MS=86400000
```

### Frontend (`frontend/.env.local`)

```env
NEXT_PUBLIC_API_URL=http://localhost:5000
API_URL=http://localhost:5000

# Used by src/proxy.ts for server-side JWT verification
JWT_ACCESS_SECRET=change_this_to_match_backend_access_secret
```

---

## 9. API Documentation

### Interactive Docs

- Swagger UI: `GET /docs`

### Representative Endpoints

| Domain | Method | Endpoint | Description |
|---|---|---|---|
| Auth | POST | `/auth/register` | Register admin/doctor account |
| Auth | POST | `/auth/login` | Login and set auth cookies |
| Auth | POST | `/auth/refresh` | Rotate refresh token and issue new access token |
| Auth | POST | `/auth/logout` | Revoke refresh token and clear cookies |
| Auth | GET | `/auth/me` | Get current authenticated user |
| Patient | POST | `/patient` | Create patient profile + set patient session cookie |
| Patient | POST | `/patient/check-phone` | Identify existing patient by phone |
| Flow | GET | `/flows` | Public flow listing |
| Visit | POST | `/visit/check-in` | Create visit and enqueue patient |
| Visit | GET | `/visit?patientId=...` | Get all visits of patient |
| Visit | GET | `/visit/central-queue` | Global queue view |
| Visit | POST | `/visit/visit-room/:id/call` | Start current room service |
| Visit | POST | `/visit/visit-room/:id/complete` | Complete room service step |
| Visit | POST | `/visit/visit-room/:id/skip` | Skip room step |
| Room | GET | `/room/dashboard` | Room-wise queue/waiting overview |
| Room | GET | `/room/:id/queue` | Queue of a specific room |
| Admin | GET | `/admin/flows` | Flow template management (admin only) |
| Admin | GET | `/admin/priority-rules` | Priority rules management (admin only) |

### Sample Request/Response

#### 1) Register

```http
POST /auth/register
Content-Type: application/json

{
  "email": "admin@hospital.local",
  "password": "StrongPassword123",
  "role": "ADMIN"
}
```

```json
{
  "user": {
    "id": "d4e3b0c0-8e39-4d81-b23d-86bd63de7d92",
    "email": "admin@hospital.local",
    "role": "ADMIN"
  },
  "accessToken": "<jwt>",
  "refreshToken": "<jwt>"
}
```

#### 2) Create Patient

```http
POST /patient
Content-Type: application/json

{
  "name": "Nguyen Van A",
  "email": "patient@example.com",
  "phone": "0912345678",
  "yearOfBirth": 1990,
  "patientTypeId": 1
}
```

```json
{
  "id": "3a0f5b6a-5a75-4f6a-a76f-8a3f6d3bd31a",
  "name": "Nguyen Van A",
  "phone": "0912345678",
  "yearOfBirth": 1990,
  "patientTypeId": 1
}
```

#### 3) Visit Check-in

```http
POST /visit/check-in
Content-Type: application/json

{
  "patientId": "3a0f5b6a-5a75-4f6a-a76f-8a3f6d3bd31a",
  "flowId": 3,
  "age": 36,
  "patientTypeId": 1,
  "isEmergency": false
}
```

```json
{
  "id": "f5fbe2b4-6525-43ff-a5d1-f95f0b083fbb",
  "patientId": "3a0f5b6a-5a75-4f6a-a76f-8a3f6d3bd31a",
  "flowId": 3,
  "status": "WAITING",
  "visitAccessToken": "<hmac-token>"
}
```

---

## 10. Real-time Communication

Real-time updates are implemented using **Socket.IO**.

### Server Gateway

- Namespace: `/`
- CORS: configurable via `FRONTEND_URL`
- Client events:
  - `join-room` with `{ roomId }`
  - `leave-room` with `{ roomId }`
- Server events:
  - `room:{roomId}:queue-updated`
  - `room:{roomId}:doctors-updated`

### Event Triggers

- Queue updates emitted after:
  - patient call
  - visit-room completion
  - visit-room skip
- Doctor updates emitted after:
  - doctor check-in
  - doctor check-out

This enables live dashboards and queue screens without manual polling.


---

## 11. Performance & Optimization Concept

The architecture improves operational performance by combining:

- **Flow decomposition**: each visit is split into sequenced, dependency-aware steps.
- **Adaptive capacity**: room throughput adapts to active doctor availability.
- **Queue-time minimization**: route selection uses queue and processing estimates.
- **Priority stratification**: emergency and high-risk profiles can be escalated.
- **Live synchronization**: room dashboards stay current through sockets.

Expected institutional outcomes include:

- Reduced average waiting times
- Better room utilization
- Increased doctor productivity visibility
- More predictable patient movement through services

---

## 12. Roadmap / Future Improvements

- Add **observability stack** (OpenTelemetry + tracing + metrics dashboards).
- Introduce **predictive wait-time model** from historical room performance.
- Add **appointment pre-booking** and no-show handling.
- Implement **multi-hospital / tenant support**.
- Harden API with **rate limiting**, audit logs, and stricter endpoint guards.
- Add **comprehensive automated tests** (unit, integration, e2e, socket flows).
- Provide **seed scripts and fixtures** for development/demo environments.
- Align infrastructure artifacts (DB provider consistency across Prisma and Docker).

---

## 13. Contributors

### 👨‍💻 Lê Huỳnh Thành – Fullstack Developer

- Architected and developed the entire system end-to-end
- Designed patient flow optimization engine and queue management logic
- Implemented backend services using NestJS and Prisma
- Built responsive frontend using Next.js, TailwindCSS, and shadcn/ui
- Integrated real-time communication with Socket.IO
- Designed secure authentication and authorization mechanisms (JWT, RBAC, HMAC tokens)

