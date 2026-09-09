# Conda Environment Setup Guide

## 🐍 Using Conda with Phoenix Scanner Tests

You're using **Conda** (Anaconda/Miniconda), which requires slightly different dependency installation.

---

## 🔍 How to Tell You're in Conda

Your terminal prompt shows:
```bash
(base) Mac:unit_tests francescocipollone$
 ^^^^
 This means you're in conda's base environment
```

---

## ✅ Quick Fix (Already Applied!)

Dependencies have been installed in your conda environment using:
```bash
pip3 install -r ../phoenix-scanner-client/requirements.txt
pip3 install -r requirements.txt
```

---

## 🚀 Running Tests

Now you can run tests normally:

```bash
cd {PROJECT_ROOT}

# Quick test
python3 quick_test.py

# Full test suite
python3 run_tests.py --config test_config.yaml

# Verbose mode
python3 run_tests.py --config test_config.yaml --verbose
```

---

## 📦 Two Options for Managing Dependencies

### **Option 1: Use Conda Base Environment** (Current Setup) ✅

**Pros**: Simple, works immediately
**Cons**: Mixes project dependencies with base environment

**Commands**:
```bash
# You're already here!
pip install -r requirements.txt
python3 run_tests.py --config test_config.yaml
```

---

### **Option 2: Create Dedicated Conda Environment** (Recommended for Production)

**Pros**: Clean isolation, no conflicts
**Cons**: Extra setup step

**Setup**:
```bash
# Create new conda environment
conda create -n phoenix-scanner python=3.11 -y

# Activate it
conda activate phoenix-scanner

# Install dependencies
cd /path/to/unit_tests
pip install -r ../phoenix-scanner-client/requirements.txt
pip install -r requirements.txt

# Run tests
python run_tests.py --config test_config.yaml
```

**Daily Use**:
```bash
# Activate environment
conda activate phoenix-scanner

# Run tests
cd /path/to/unit_tests
python run_tests.py --config test_config.yaml

# Deactivate when done
conda deactivate
```

---

## 🔄 Switching Between Environments

### **Check Current Environment**:
```bash
conda env list
# The active environment has a * next to it
```

### **List Environments**:
```bash
conda env list
# Output:
# base                  *  /opt/anaconda3
# phoenix-scanner          /opt/anaconda3/envs/phoenix-scanner
```

### **Switch Environments**:
```bash
# Activate specific environment
conda activate phoenix-scanner

# Go back to base
conda activate base

# Deactivate all conda
conda deactivate
```

---

## 🆘 Troubleshooting

### **Error: "No module named 'rich'" (in conda)**

**Solution 1**: Install in current conda environment
```bash
# Check which Python you're using
which python
python --version

# Install dependencies
pip install -r ../phoenix-scanner-client/requirements.txt
pip install -r requirements.txt
```

**Solution 2**: Use conda packages when possible
```bash
# Some packages are available via conda
conda install -c conda-forge pytest pyyaml requests

# Install remaining via pip
pip install rich websockets
```

### **Error: "conda: command not found"**

You're not in conda anymore. Use regular Python:
```bash
python3 -m pip install -r requirements.txt
python3 run_tests.py --config test_config.yaml
```

### **Different Python versions between conda and system**

```bash
# Check conda Python
conda activate base
python --version

# Check system Python
conda deactivate
python3 --version
```

---

## 📊 Conda vs System Python

| Aspect | Conda Python | System Python |
|--------|--------------|---------------|
| **Activated when** | Terminal shows `(base)` or `(env_name)` | No conda prefix in prompt |
| **Python location** | `/opt/anaconda3/bin/python` | `/usr/local/bin/python3` |
| **Install command** | `pip install` or `conda install` | `python3 -m pip install` |
| **Good for** | Data science, multiple projects | System-wide tools |

---

## ✅ Current Status

**You're using**: Conda base environment
**Python version**: 3.11.13
**Dependencies**: ✅ Installed
**Tests**: ✅ Ready to run

---

## 🎯 Recommendation

### **For Development/Testing** (Current):
Stay in conda base - it's working fine! ✅

### **For Production/CI/CD**:
Create dedicated environment:
```bash
conda create -n phoenix-scanner python=3.11 -y
conda activate phoenix-scanner
pip install -r requirements.txt
```

---

## 📚 Quick Commands Reference

```bash
# Check if in conda
echo $CONDA_DEFAULT_ENV

# List conda environments
conda env list

# Create new environment
conda create -n myenv python=3.11

# Activate environment
conda activate myenv

# Deactivate
conda deactivate

# Install packages
pip install package_name
# OR
conda install package_name

# Remove environment
conda env remove -n myenv
```

---

## 🔧 Auto-Setup Script for Conda

Created a conda-aware setup script:

```bash
./setup_dependencies.sh
# Detects conda and installs accordingly
```

---

## ✨ Best Practices

### **1. Keep Base Environment Clean**
```bash
# Create project-specific environment
conda create -n phoenix-scanner python=3.11
conda activate phoenix-scanner
```

### **2. Use requirements.txt**
```bash
# Export your environment
pip freeze > my_requirements.txt

# Share with team
pip install -r my_requirements.txt
```

### **3. Document Your Setup**
```bash
# Add to your README:
# Environment: conda (phoenix-scanner)
# Python: 3.11
# Setup: conda activate phoenix-scanner && pip install -r requirements.txt
```

---

## 📝 Summary

**✅ Issue Fixed**: Dependencies now installed in conda environment

**Run tests**:
```bash
cd unit_tests
python3 run_tests.py --config test_config.yaml
```

**Your setup**:
- Conda: ✅ Active (base environment)
- Python: 3.11.13
- Dependencies: ✅ Installed
- Ready: ✅ Yes!

---

**Date**: November 12, 2024  
**Environment**: Conda (base)  
**Status**: ✅ Ready to run tests

