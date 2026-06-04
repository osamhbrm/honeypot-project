#!/bin/bash
yum update -y
yum install -y docker
systemctl enable docker
systemctl start docker
usermod -aG docker ec2-user

echo "Port 2222" >> /etc/ssh/sshd_config
systemctl restart sshd

sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

mkdir -p /home/ec2-user/honeypot
cd /home/ec2-user/honeypot

cat << 'EOF' > docker-compose.yml
version: '3.8'

services:
  # مصيدة الـ SSH (كاوري) تستمع على بورت 22 الخارجي
  cowrie:
    image: cowrie/cowrie:latest
    ports:
      - "22:2222"
    volumes:
      - cowrie-data:/cowrie/cowrie-git/var/log/cowrie

  # تطبيق الفلاسك (المصيدة والداشبورد)
  flask-honeypot:
    image: 612356096472.dkr.ecr.us-east-1.amazonaws.com/honeypot:latest
    ports:
      - "80:5000"
      - "5000:5000"
    volumes:
      - cowrie-data:/app/cowrie_logs:ro
    environment:
      - FLASK_ENV=development
    depends_on:
      - cowrie

volumes:
  cowrie-data:
EOF

chown -R ec2-user:ec2-user /home/ec2-user/honeypot

aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 612356096472.dkr.ecr.us-east-1.amazonaws.com

/usr/local/bin/docker-compose up -d