# Simple Library Management System

## Overview
A Flask and SQLite-based library management system with JWT authentication for managing books, customers, and loans.

## Features
- Book, Customer, and Loan Management
- JWT Authentication for registration and login

## Database Schema
- **Books:** `Id` (PK), `Name`, `Author`, `Year Published`, `Type` (1/2/3)
- **Customers:** `Id` (PK), `Name`, `City`, `Age`
- **Loans:** `CustID`, `BookID`, `LoanDate`, `ReturnDate`

## Setup
1. Clone the repo and `cd` into it
2. Create the virtual env
3. Install dependencies: `pip install -r requirements.txt`
4. Start the server
5. Open live index.html


