terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
      # aws            = the security (delegated administrator) account
      # aws.management = the organization's management account, used only to delegate admin
      configuration_aliases = [aws.management]
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}
