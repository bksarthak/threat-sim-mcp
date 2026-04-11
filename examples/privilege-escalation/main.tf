provider "aws" {
  region = "us-east-1"
}

# 1. Unauthenticated Public Cloud Function
resource "aws_lambda_function" "data_processor" {
  filename      = "function.zip"
  function_name = "WebhookProcessor"
  role          = aws_iam_role.lambda_exec_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
}

# Threat: Making Lambda publicly accessible over the internet without an Auth layer (API Gateway).
resource "aws_lambda_function_url" "public_endpoint" {
  function_name      = aws_lambda_function.data_processor.function_name
  authorization_type = "NONE" 
}

# 2. Compute Execution Role
resource "aws_iam_role" "lambda_exec_role" {
  name = "LambdaDataProcessorRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# 3. Privilege Escalation Vector (iam:PassRole + ec2:RunInstances)
# If an attacker achieves RCE via the unauthenticated webhook webhook, they can launch a new EC2 instance 
# and pass it an existing Administrator role, bypassing their limited initial surface.
resource "aws_iam_role_policy" "shadow_admin_escalation" {
  name = "DevOpsAutomationPolicy"
  role = aws_iam_role.lambda_exec_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:PassRole"
        ]
        Effect   = "Allow"
        Resource = "*" # Threat: Not constrained to specific lower-tier roles
      },
      {
         Action = [
           "ec2:RunInstances"
         ]
         Effect   = "Allow"
         Resource = "*"
      }
    ]
  })
}
