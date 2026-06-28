cmake_minimum_required(VERSION 3.10)
project(SecurityAuditMockApp CXX)

# Crypto Transport Provider - Contains CVE-2014-0160 (Heartbleed exploit vector)
find_package(OpenSSL 1.0.1f REQUIRED)

# Structural Threading Engine Module - Clean library package baseline
FIND_PACKAGE(Threads REQUIRED)