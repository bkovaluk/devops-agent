terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

# The tooling account runs the agent. Each member account is reached through a role this
# configuration's credentials may assume there, all in the agent's one region.
provider "aws" {
  region = var.region
}

provider "aws" {
  alias  = "member_a"
  region = var.region

  assume_role {
    role_arn = var.member_a_deploy_role_arn
  }
}

provider "aws" {
  alias  = "member_b"
  region = var.region

  assume_role {
    role_arn = var.member_b_deploy_role_arn
  }
}

data "aws_caller_identity" "tooling" {}

module "devops_agent" {
  source = "../.."

  environment  = var.environment
  package_path = var.package_path

  organization_id    = var.organization_id
  member_role_name   = "devops-agent-read"
  member_external_id = var.external_id
  allowed_account_ids = [
    data.aws_caller_identity.tooling.account_id,
    var.member_a_account_id,
    var.member_b_account_id,
  ]

  alarm_actions = var.alarm_actions

  tags = {
    Project = "devops-agent"
  }
}

module "member_a" {
  source = "../../member"

  providers = {
    aws = aws.member_a
  }

  investigator_role_arn = module.devops_agent.role_arn
  central_event_bus_arn = module.devops_agent.central_event_bus_arn
  role_name             = "devops-agent-read"
  external_id           = var.external_id

  tags = {
    Project = "devops-agent"
  }
}

module "member_b" {
  source = "../../member"

  providers = {
    aws = aws.member_b
  }

  investigator_role_arn = module.devops_agent.role_arn
  central_event_bus_arn = module.devops_agent.central_event_bus_arn
  role_name             = "devops-agent-read"
  external_id           = var.external_id

  tags = {
    Project = "devops-agent"
  }
}
