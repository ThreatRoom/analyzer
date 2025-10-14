#!/bin/bash

# Office File Analyzer - GitHub Setup Script
# Updated for ~/Projects/analyzer-test-local/ location

echo "🐙 Office File Analyzer - GitHub Setup"
echo "======================================"

# Check if we're in the right directory
if [ ! -f "analyze_office.py" ]; then
    echo "❌ Error: Not in the Office File Analyzer directory"
    echo "Please run this script from ~/Projects/analyzer-test-local/"
    exit 1
fi

# Prompt for GitHub username
read -p "Enter your GitHub username: " GITHUB_USERNAME

if [ -z "$GITHUB_USERNAME" ]; then
    echo "❌ Error: GitHub username is required"
    exit 1
fi

# Confirm repository name
read -p "Enter repository name (default: analyzer): " REPO_NAME
REPO_NAME=${REPO_NAME:-analyzer}

echo ""
echo "📋 Setup Summary:"
echo "   GitHub Username: $GITHUB_USERNAME"
echo "   Repository Name: $REPO_NAME"
echo "   Repository URL: https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"
echo ""

read -p "Continue with setup? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ]; then
    echo "Setup cancelled."
    exit 1
fi

echo ""
echo "🔧 Setting up GitHub repository..."

# Check if origin already exists
if git remote get-url origin >/dev/null 2>&1; then
    echo "⚠️  Remote 'origin' already exists. Removing it first..."
    git remote remove origin
fi

# Add the GitHub repository as origin
echo "📡 Adding GitHub repository as origin..."
git remote add origin "https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"

# Push main branch
echo "🚀 Pushing main branch..."
git push -u origin main

# Push all branches
echo "🌿 Pushing all branches..."
git push -u origin --all

# Show status
echo ""
echo "✅ Setup completed successfully!"
echo ""
echo "📊 Repository Status:"
git remote -v
echo ""
git branch -a
echo ""

echo "🎉 Your Office File Analyzer is now on GitHub!"
echo "   📍 Repository URL: https://github.com/$GITHUB_USERNAME/$REPO_NAME"
echo ""
echo "🔗 Next Steps:"
echo "   1. Visit your repository: https://github.com/$GITHUB_USERNAME/$REPO_NAME"
echo "   2. Create a Pull Request if you have feature branches"
echo "   3. Review and merge your changes"
echo "   4. Share your analyzer with the community!"
echo ""
echo "📖 Documentation: See README.md for usage instructions"
echo "🧪 Testing: Run 'python test_basic.py' to verify functionality"