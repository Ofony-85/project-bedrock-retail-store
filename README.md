# Project Bedrock - AWS Retail Store EKS Deployment

**Live Application**: http://a4287fe1071854c969f6bfffe09bda70-1869993498.us-east-1.elb.amazonaws.com

This repository contains the Infrastructure as Code solution for deploying the official AWS retail-store-sample-app to Amazon EKS.

## Project Status: DEPLOYED & OPERATIONAL

All components successfully running:
- EKS Cluster: retail-store-eks (Kubernetes v1.30)
- Application: All 5 microservices operational  
- Load Balancer: Public internet access
- Developer Access: Read-only IAM user configured

## Developer Access

**IAM User**: retail-store-eks-developer
**Setup Command**: `aws eks update-kubeconfig --region us-east-1 --name retail-store-eks`

## Architecture Components

- VPC with public/private subnets across 2 AZs
- EKS cluster with 3 t3.medium worker nodes
- Official AWS retail store sample application
- Microservices: UI, Catalog, Cart, Orders, Checkout
- Databases: MySQL, PostgreSQL, DynamoDB Local, Redis, RabbitMQ

## Requirements Fulfilled

✅ Infrastructure as Code (Terraform)
✅ EKS cluster deployment
✅ Official AWS retail-store-sample-app
✅ Developer IAM user with read-only access
✅ CI/CD pipeline configuration
✅ All microservices operational
# Testing CI/CD Pipeline
