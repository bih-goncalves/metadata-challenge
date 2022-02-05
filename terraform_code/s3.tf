resource "aws_s3_bucket" "bucket" {
  provider = aws.profile_2

  bucket = local.bucket_name
  acl    = "private"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.bianca_test.arn}"
      },
      "Action": "s3:*",
      "Resource": [
          "arn:aws:s3:::${local.bucket_name}/*",
          "arn:aws:s3:::${local.bucket_name}"
      ]
    }
  ]
}
POLICY
}
