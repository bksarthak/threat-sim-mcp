provider "aws" {
  region = "us-east-1"
}

# 1. Edge: Public Application Load Balancer
resource "aws_lb" "web_alb" {
  name               = "external-web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = ["subnet-abcde012", "subnet-bcde012a"]
}

resource "aws_security_group" "alb_sg" {
  name        = "alb-public-sg"
  description = "Public ALB allowed over 80"

  ingress {
    description = "Allow port 80"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 2. Compute Target: EC2 running standard AMI, missing IMDSv2 enforcement
resource "aws_instance" "web_server" {
  ami           = "ami-1234567890abcdef0"
  instance_type = "t2.micro"
  
  iam_instance_profile = aws_iam_instance_profile.web_server_profile.name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]

  # Threat: Using V1 Metadata service opens up SSRF credential theft
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # Optional enables IMDSv1
  }
}

resource "aws_security_group" "ec2_sg" {
  name        = "web-server-sg"
  description = "EC2 target group SG"
  
  ingress {
    description     = "Allow from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    description = "Unrestricted outbound for updates/reverse-shells"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. Transitive Pivot: Overly Permissive IAM Role attached to the EC2
resource "aws_iam_role" "web_server_role" {
  name = "WebServerRole"

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

resource "aws_iam_role_policy" "excessive_db_access" {
  name = "WildcardDataLakeAccess"
  role = aws_iam_role.web_server_role.id

  # Threat: Providing full S3 permissions rather than strictly scoping to a specific ARN
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = "*" # Critical: Allows lateral scanning of ALL buckets
      }
    ]
  })
}

resource "aws_iam_instance_profile" "web_server_profile" {
  name = "WebServerInstanceProfile"
  role = aws_iam_role.web_server_role.name
}

# 4. Target: Highly Sensitive "Internal" Data Lake
# While the bucket is properly blocking public access, the compromised EC2 role has transitive access to it.
resource "aws_s3_bucket" "private_financials" {
  bucket = "internal-financial-records-2026"
}

resource "aws_s3_bucket_public_access_block" "private_financials_block" {
  bucket                  = aws_s3_bucket.private_financials.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
