provider "aws" {
  region = "us-east-1" # يمكنك تغيير المنطقة حسب رغبتك
}

# 2. إنشاء شبكة VPC وبوابة الإنترنت (IGW)
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "main-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "main-igw"
  }
}

# 3. إنشاء Subnet عام وتوجيه المرور للـ IGW
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true # لجعل أي سيرفر داخلها يأخذ Public IP تلقائياً

  tags = {
    Name = "public-subnet"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}
data "http" "my_public_ip" {
  url = "https://ifconfig.me/ip"
}

# 4. إنشاء الـ Security Group للسيرفر (يسمح بالـ SSH كمثال)
resource "aws_security_group" "ec2_sg" {
  name        = "ec2-allow-ssh"
  description = "Allow SSH inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # لأمان أكبر، يفضل وضع الـ IP الخاص بك هنا فقط
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # لأمان أكبر، يفضل وضع الـ IP الخاص بك هنا فقط
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.my_public_ip.response_body)}/32"] # لأمان أكبر، يفضل وضع الـ IP الخاص بك هنا فقط
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 5. إنشاء الـ IAM Role والـ Instance Profile للقراءة من ECR
resource "aws_iam_role" "ecr_read_role" {
  name = "ec2-ecr-read-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# ربط الصلاحية الجاهزة AmazonEC2ContainerRegistryReadOnly بالـ Role
resource "aws_iam_role_policy_attachment" "ecr_read_attach" {
  role       = aws_iam_role.ecr_read_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# 2. ربط صلاحية الـ SSM بالـ Role لتمكين الـ Session Manager
resource "aws_iam_role_policy_attachment" "ssm_managed_attach" {
  role       = aws_iam_role.ecr_read_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# 3. إنشاء الـ Instance Profile وربطه بالـ Role نفسه ليمرر الصلاحيتين معاً للسيرفر
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-ecr-read-profile"
  role = aws_iam_role.ecr_read_role.name
}

data "aws_ami" "image" {

  most_recent = true
  owners      = ["amazon"]


  filter {
    name   = "name"
    values = ["al2023-ami-2023*-kernel-6.1-x86_64*"]
  }
}

# 6. إنشاء الـ EC2 Instance وربطه بكل ما سبق
resource "aws_instance" "my_ec2" {
  ami                  = data.aws_ami.image.image_id # تأكد من أن الـ AMI متوافق مع منطقتك (هذا لـ Ubuntu في us-east-1)
  instance_type        = "t3.small"
  subnet_id            = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  user_data_base64 = filebase64("${path.module}/userdata.sh")
  lifecycle {
    create_before_destroy = true
  }


  tags = {
    Name = "Public-EC2-with-ECR-Read"
  }
}# 7. مخرجات النظام (Output): طباعة الـ IP العام للسيرفر فور إنشائه
output "ec2_public_ip" {
  description = "The public IP address of the Honeypot EC2 instance"
  value       = aws_instance.my_ec2.public_ip
}