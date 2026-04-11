provider "aws" {
  region = "us-east-1"
}

# Vulnerable Network Boundary
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic - Extreme Threat"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow all"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Vulnerable Storage (Data Leakage)
resource "aws_s3_bucket" "prod_data" {
  bucket = "company-financial-records"
}

resource "aws_s3_bucket_public_access_block" "prod_data_public_access" {
  bucket = aws_s3_bucket.prod_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "prod_data_acl" {
  bucket = aws_s3_bucket.prod_data.id
  acl    = "public-read"
  depends_on = [aws_s3_bucket_public_access_block.prod_data_public_access]
}
