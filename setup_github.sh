#!/bin/bash

# GitHub Repository Setup Script
# Replace 'YOUR_GITHUB_USERNAME' with your actual GitHub username

GITHUB_USERNAME="YOUR_GITHUB_USERNAME"
REPO_NAME="analyzer"

echo "Setting up GitHub remote repository..."
echo "Repository: https://github.com/${GITHUB_USERNAME}/${REPO_NAME}"

# Add the remote origin
git remote add origin "https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git"

# Create and push main branch
echo "Creating main branch..."
git checkout main 2>/dev/null || git checkout -b main

# Create initial commit on main if needed
if [ $(git rev-list --count HEAD) -eq 0 ]; then
    echo "Creating initial commit on main..."
    echo "# Office File Analyzer

A comprehensive Python tool for analyzing Microsoft Office documents to detect malicious content.

This repository contains the complete implementation of the Office File Analyzer with all features including macro analysis, threat detection, and comprehensive reporting.

## Quick Start

1. Install dependencies: \`pip install -r requirements.txt\`
2. Run analysis: \`python analyze_office.py your_document.docx\`

See README.md for complete documentation." > README_MAIN.md
    
    git add README_MAIN.md
    git commit -m "Initial commit: Office File Analyzer project"
fi

# Push main branch
echo "Pushing main branch..."
git push -u origin main

# Push feature branch
echo "Pushing feature branch..."
git checkout feature/office-analyzer-implementation
git push -u origin feature/office-analyzer-implementation

echo "Repository setup complete!"
echo ""
echo "Next steps:"
echo "1. Go to https://github.com/${GITHUB_USERNAME}/${REPO_NAME}"
echo "2. Create a pull request from 'feature/office-analyzer-implementation' to 'main'"
echo "3. Review and merge the pull request"
echo ""
echo "Note: Make sure to replace 'YOUR_GITHUB_USERNAME' with your actual GitHub username"
echo "and ensure the repository exists on GitHub before running this script."