provider "aws" {
  profile = "" # insert profile name
  alias   = "profile_1"
  region  = "us-east-1"

  default_tags {
    tags = {
      Product     = local.product_name
      Environment = title(local.env)
      Monitoring  = "CloudWatch"
      TechContact = "DevOps"
      Deprecate   = "N"
    }
  }
}

provider "aws" {
  profile = "" # insert another profile name
  alias   = "profile_2"
  region  = "us-east-2"

  default_tags {
    tags = {
      Product     = local.product_name
      Environment = title(local.env)
      Monitoring  = "CloudWatch"
      TechContact = "DevOps"
      Deprecate   = "N"
    }
  }
}

terraform {
  required_version = ">= 0.13.5"

  backend "s3" {
    profile = "" # insert profile name
    bucket  = "" # insert bucket name for TF state
    key     = "bianca-sandbox/tfstate/terraform.tfstate"
    region  = "us-east-1"
  }

  required_providers {
    aws = "~> 3.60"
    tls = "~> 3.1.0"
  }
}

