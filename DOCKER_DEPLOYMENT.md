# Docker Deployment Guide

This guide covers deploying **carlcare-imei** with **db-browser-for-sqlite** to cloud platforms.

## Prerequisites

- Docker installed locally (for testing)
- Cloud account (AWS, Google Cloud, Azure, DigitalOcean, Heroku, etc.)
- Docker Hub account (optional, for image registry)

---

## Local Deployment

### 1. Build and Run Locally

```bash
# Clone the repository
git clone https://github.com/morshedgtc-lang/carlcare-imei.git
cd carlcare-imei

# Create .env file
cp .env.example .env

# Edit .env with your JWT_SECRET
echo "JWT_SECRET=$(openssl rand -base64 32)" >> .env

# Build and run with docker-compose
docker-compose up --build
```

### 2. Access Services

- **Application**: http://localhost:3000
- **Database Browser**: http://localhost:8080
- **Health Check**: http://localhost:3000/health

### 3. Stop Services

```bash
docker-compose down
```

---

## Cloud Deployment Options

### **Option 1: AWS ECS (Elastic Container Service)**

#### Steps:

1. **Push to ECR (Elastic Container Registry)**
   ```bash
   # Create ECR repository
   aws ecr create-repository --repository-name carlcare-imei --region us-east-1

   # Get login token
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

   # Build and push
   docker build -t carlcare-imei:latest .
   docker tag carlcare-imei:latest <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/carlcare-imei:latest
   docker push <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/carlcare-imei:latest
   ```

2. **Create ECS Task Definition**
   - Use ECR image URI
   - Set memory: 512 MB
   - Set CPU: 256
   - Port mapping: 3000
   - Add environment variables (JWT_SECRET, etc.)

3. **Create ECS Service**
   - Launch type: Fargate
   - VPC: Default or custom
   - Load balancer: Application Load Balancer

4. **Database Browser (Optional)**
   - Deploy as separate ECS task or EC2 instance
   - Or use RDS with AWS Secrets Manager

---

### **Option 2: Google Cloud Run**

#### Steps:

1. **Push to Google Container Registry**
   ```bash
   # Configure gcloud
   gcloud auth configure-docker

   # Build and push
   docker build -t gcr.io/<PROJECT_ID>/carlcare-imei:latest .
   docker push gcr.io/<PROJECT_ID>/carlcare-imei:latest
   ```

2. **Deploy to Cloud Run**
   ```bash
   gcloud run deploy carlcare-imei \
     --image gcr.io/<PROJECT_ID>/carlcare-imei:latest \
     --platform managed \
     --region us-central1 \
     --port 3000 \
     --set-env-vars JWT_SECRET=<YOUR_SECRET> \
     --memory 512Mi \
     --cpu 1
   ```

3. **Deploy db-browser separately**
   ```bash
   gcloud run deploy db-browser \
     --image coleifer/sqlite-web:latest \
     --platform managed \
     --region us-central1 \
     --port 8080 \
     --memory 256Mi
   ```

---

### **Option 3: Azure Container Instances**

#### Steps:

1. **Push to Azure Container Registry**
   ```bash
   # Create container registry
   az acr create --resource-group <RG> --name <REGISTRY_NAME> --sku Basic

   # Build and push
   az acr build --registry <REGISTRY_NAME> --image carlcare-imei:latest .
   ```

2. **Deploy Container Instance**
   ```bash
   az container create \
     --resource-group <RG> \
     --name carlcare-imei-app \
     --image <REGISTRY_NAME>.azurecr.io/carlcare-imei:latest \
     --ports 3000 \
     --environment-variables JWT_SECRET=<YOUR_SECRET> \
     --registry-login-server <REGISTRY_NAME>.azurecr.io \
     --registry-username <USERNAME> \
     --registry-password <PASSWORD>
   ```

---

### **Option 4: DigitalOcean App Platform**

#### Steps:

1. **Connect GitHub Repository**
   - Link carlcare-imei GitHub repo to DigitalOcean

2. **Create App Spec (app.yaml)**
   ```yaml
   name: carlcare-imei
   services:
   - name: carlcare-api
     github:
       repo: morshedgtc-lang/carlcare-imei
       branch: main
     build_command: npm install
     run_command: npm start
     http_port: 3000
     envs:
     - key: JWT_SECRET
       scope: RUN_AND_BUILD_TIME
       value: ${JWT_SECRET}
   - name: db-browser
     image:
       registry_type: DOCKER_HUB
       registry: coleifer/sqlite-web
     http_port: 8080
   ```

3. **Deploy**
   - Push to GitHub
   - DigitalOcean auto-deploys on push

---

### **Option 5: Heroku (Deprecated but still available)**

#### Steps:

1. **Create Heroku App**
   ```bash
   heroku create carlcare-imei
   ```

2. **Add Procfile**
   ```
   web: npm start
   ```

3. **Set Environment Variables**
   ```bash
   heroku config:set JWT_SECRET=<YOUR_SECRET>
   heroku config:set NODE_ENV=production
   ```

4. **Deploy**
   ```bash
   git push heroku main
   ```

---

### **Option 6: Self-Hosted (VPS/Dedicated Server)**

#### Steps:

1. **SSH into Server**
   ```bash
   ssh user@your-server.com
   ```

2. **Install Docker & Docker Compose**
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
   sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

3. **Clone and Deploy**
   ```bash
   git clone https://github.com/morshedgtc-lang/carlcare-imei.git
   cd carlcare-imei
   cp .env.example .env
   # Edit .env
   docker-compose up -d
   ```

4. **Setup Reverse Proxy (Nginx)**
   ```nginx
   server {
       listen 80;
       server_name yourdomain.com;
       
       location / {
           proxy_pass http://localhost:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
       }
   }
   
   server {
       listen 80;
       server_name db.yourdomain.com;
       
       location / {
           proxy_pass http://localhost:8080;
           proxy_set_header Host $host;
       }
   }
   ```

5. **Enable SSL (Let's Encrypt)**
   ```bash
   sudo apt-get install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com -d db.yourdomain.com
   ```

---

## Environment Variables

Create a `.env` file in the root directory:

```env
# Application
NODE_ENV=production
PORT=3000
JWT_SECRET=your-secret-key-here

# Database
DB_PATH=/app/data/carlcare.db

# Docker Ports
APP_PORT=3000
DB_BROWSER_PORT=8080
```

---

## Security Best Practices

1. **Use environment secrets** - Never commit `.env` files
2. **Enable HTTPS** - Use reverse proxy with SSL/TLS
3. **Rate limiting** - Already configured in app.js
4. **Database access** - Use firewall rules to restrict db-browser access
5. **Regular backups** - Backup `/data/carlcare.db` regularly
6. **Health checks** - Enabled in docker-compose.yml
7. **Read-only mode** - db-browser runs in read-only mode

---

## Monitoring & Logs

### Docker Logs

```bash
# Application logs
docker-compose logs carlcare-app

# Database browser logs
docker-compose logs db-browser

# Live logs
docker-compose logs -f
```

### Health Check

```bash
curl http://localhost:3000/health
# Response: {"status":"ok","timestamp":"2024-06-16T..."}
```

---

## Database Backup & Restore

### Backup

```bash
# Copy database file
docker-compose exec carlcare-app cp /app/data/carlcare.db /app/data/backup_$(date +%Y%m%d_%H%M%S).db

# Or direct file copy
cp data/carlcare.db data/backup_$(date +%Y%m%d_%H%M%S).db
```

### Restore

```bash
cp data/backup_20240616_120000.db data/carlcare.db
docker-compose restart carlcare-app
```

---

## Troubleshooting

### Port Already in Use
```bash
# Change ports in docker-compose.yml or .env
# Or kill process using port
lsof -i :3000
kill -9 <PID>
```

### Database Connection Issues
```bash
docker-compose exec carlcare-app cat /app/data/carlcare.db
# Check if file exists and has permissions
```

### Out of Memory
```bash
# Increase Docker memory limit in docker-compose.yml or Docker Desktop settings
```

---

## Support & Documentation

- [Docker Official Docs](https://docs.docker.com/)
- [Docker Compose Docs](https://docs.docker.com/compose/)
- [sqlite-web GitHub](https://github.com/coleifer/sqlite-web)
- [Express.js Docs](https://expressjs.com/)

