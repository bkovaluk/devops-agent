terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "devops_agent" {
  source = "../.."

  environment  = var.environment
  package_path = var.package_path

  alarm_actions = var.alarm_actions

  tags = {
    Project = "devops-agent"
  }
}
