# Online Shopping Sysyem (final project)
High-Concurrency Client-Server Network Service System.

## Task Assignment
![Task Assignment](https://github.com/user-attachments/assets/7d19a2ce-cb7d-4f95-bf83-ec358f6dab1d)

## Overall Architecture
![Overall Architecture](https://github.com/user-attachments/assets/ea9184e9-9e60-45f7-92e4-6ac19473faad)

## Certificate Diagram
![Certificate Diagram](./docs/certificate-diagram.png)

## Master-Worker Pattern

#### Master
<img src="./docs/master-diagram.png" width="50%" alt="Master Diagram" />

#### Worker
<img src="./docs/worker-diagram.png" alt="Worker Diagram" />

## Build & Run

### Build
Compile the project:
```bash
make
```

### Run Server
```bash
make run-server
```

### Run Client
```bash
make run-client
```

### Run Stress Test
```bash
make run-stress
```