provider "aws" {
  region  = "eu-north-1"  # Stockholm, Sweden
  profile = "terraform-user"
}

# Create an S3 bucket
resource "aws_s3_bucket" "file_storage" {
  bucket = "my-app-file-storage-bucket"  # Change to a unique name
}

# Block public access to the bucket
resource "aws_s3_bucket_public_access_block" "file_storage_block" {
  bucket                  = aws_s3_bucket.file_storage.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Create an IAM role for S3 access
resource "aws_iam_role" "s3_access_role" {
  name = "terraform-s3-access-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# IAM Policy to Allow S3 Access
resource "aws_iam_policy" "s3_access_policy" {
  name        = "terraform-s3-policy"
  description = "Allows read/write access to the S3 bucket"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-file-storage-bucket",
        "arn:aws:s3:::my-app-file-storage-bucket/*"
      ]
    }
  ]
}
EOF
}

# Attach IAM Policy to Role
resource "aws_iam_role_policy_attachment" "s3_role_policy_attach" {
  role       = aws_iam_role.s3_access_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}
