# Common Installation Errors & Fixes

## ✅ All Fixed - Quick Reference Guide

---

## ❌ Error 1: Cannot Uninstall PyYAML

### **Error Message**:
```
ERROR: Cannot uninstall 'PyYAML'. It is a distutils installed project and thus 
we cannot accurately determine which files belong to it which would lead to only 
a partial uninstall.
```

### **Cause**:
- Old version of PyYAML (5.3) was installed using distutils
- Modern pip can't cleanly uninstall distutils packages
- Common on systems with mixed package managers

### **✅ Solution**:
Use `--ignore-installed` flag:
```bash
pip install --ignore-installed PyYAML -r requirements.txt
```

This installs the new version alongside the old one, with the new one taking precedence.

### **Better Long-term Solution**:
Use virtual environment to avoid system package conflicts:
```bash
# Create fresh environment
conda create -n phoenix-scanner python=3.10 -y
conda activate phoenix-scanner
pip install -r requirements.txt  # Clean install
```

---

## ❌ Error 2: Missing -r Flag

### **Error Message**:
```
ERROR: Could not find a version that satisfies the requirement requirements.txt
HINT: You are attempting to install a package literally named "requirements.txt"
```

### **Cause**:
Used `pip install requirements.txt` instead of `pip install -r requirements.txt`

### **Wrong ❌**:
```bash
pip install requirements.txt      # Tries to install package named "requirements.txt"
pip3 install requirements.txt     # Same error
```

### **Correct ✅**:
```bash
pip install -r requirements.txt   # Reads file and installs listed packages
pip3 install -r requirements.txt  # Also correct
```

### **The `-r` flag means**:
"Read the requirements from this file"

---

## ❌ Error 3: Python Version Mismatch

### **Error**: Packages installed but not found when running script

### **Cause**:
```bash
pip3 install ...     # Installs for Python 3.10
python3 script.py    # Runs with Python 3.11
```

### **✅ Solution**:
Always use `python3 -m pip`:
```bash
python3 -m pip install -r requirements.txt
# Ensures packages install for the same Python version you're using
```

---

## ❌ Error 4: Module Not Found (After Installation)

### **Error Message**:
```
ModuleNotFoundError: No module named 'rich'
```

### **Possible Causes & Solutions**:

#### **Cause A: Wrong Python Environment**
```bash
# Check which Python
which python3
python3 --version

# Check where packages are
pip list | grep rich

# If in conda (shows "(base)" in prompt)
pip install -r requirements.txt  # Install in conda

# If not in conda
python3 -m pip install -r requirements.txt
```

#### **Cause B: Virtual Environment Not Activated**
```bash
# If you created a venv:
source venv/bin/activate  # Activate it first!
pip install -r requirements.txt
```

#### **Cause C: System vs User Installation**
```bash
# Try installing for user
pip install --user -r requirements.txt
```

---

## 🔧 Complete Fix Command

For any installation issues, use this comprehensive command:

```bash
cd /path/to/unit_tests

# Install everything with all fixes
pip install --ignore-installed PyYAML -r ../phoenix-scanner-client/requirements.txt
pip install --ignore-installed PyYAML -r requirements.txt
```

**This handles**:
- ✅ PyYAML distutils conflict
- ✅ Correct -r flag usage
- ✅ All dependencies installed

---

## 📋 Installation Checklist

Before running tests, verify:

### **1. Check Python Version**
```bash
python3 --version  # Should be 3.10+
```

### **2. Check if in Conda**
```bash
# If prompt shows (base) or (env_name), you're in conda
# Use: pip install

# If no conda indicator
# Use: python3 -m pip install
```

### **3. Install Dependencies**
```bash
# In conda:
pip install --ignore-installed PyYAML -r requirements.txt

# Without conda:
python3 -m pip install --ignore-installed PyYAML -r requirements.txt
```

### **4. Verify Installation**
```bash
python3 -c "import rich; import pytest; import yaml; print('✅ OK')"
```

### **5. Test Script**
```bash
python3 run_tests.py --help  # Should show help without errors
```

---

## 🆘 Still Having Issues?

### **Nuclear Option - Fresh Start**:

```bash
# 1. Create clean conda environment
conda create -n phoenix-test python=3.10 -y
conda activate phoenix-test

# 2. Install everything fresh
cd /path/to/unit_tests
pip install -r ../phoenix-scanner-client/requirements.txt
pip install -r requirements.txt

# 3. Test
python run_tests.py --help
```

### **Check for Conflicts**:
```bash
# See what's installed
pip list

# Check for version conflicts
pip check
```

### **Reinstall Specific Package**:
```bash
# If one package is problematic
pip uninstall rich -y
pip install rich==14.2.0
```

---

## 📊 Error Summary Table

| Error | Quick Fix | Command |
|-------|-----------|---------|
| PyYAML can't uninstall | Use `--ignore-installed` | `pip install --ignore-installed PyYAML -r requirements.txt` |
| Missing -r flag | Add `-r` | `pip install -r requirements.txt` (not `pip install requirements.txt`) |
| Module not found | Match Python version | `python3 -m pip install -r requirements.txt` |
| Conda/system mismatch | Install in active env | In conda: `pip install`, Outside: `python3 -m pip install` |

---

## ✅ Your Current Status

**All errors fixed!** ✨

```bash
✓ PyYAML conflict resolved (using --ignore-installed)
✓ Correct -r flag used
✓ All dependencies installed
✓ Imports working
✓ Test script ready
```

---

## 🚀 Run Tests Now

```bash
cd {PROJECT_ROOT}

# Quick test
python3 quick_test.py

# Full test suite
python3 run_tests.py --config test_config.yaml

# Verbose output
python3 run_tests.py --config test_config.yaml --verbose
```

---

## 💡 Best Practices to Avoid These Errors

### **1. Always Use Correct Syntax**
```bash
# Correct ✅
pip install -r requirements.txt

# Wrong ❌
pip install requirements.txt
```

### **2. Match Python and Pip Versions**
```bash
# Safest approach
python3 -m pip install package
```

### **3. Use Virtual Environments**
```bash
# For each project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### **4. Document Your Environment**
```bash
# Save your working environment
pip freeze > requirements-working.txt
```

### **5. Use .gitignore**
```gitignore
# Don't commit virtual environments
venv/
*.pyc
__pycache__/
```

---

## 📚 Related Documentation

- `DEPENDENCY_FIX.md` - Python version mismatch guide
- `CONDA_SETUP.md` - Conda-specific instructions
- `setup_dependencies.sh` - Automated setup script

---

**Date**: November 12, 2024  
**Status**: ✅ All Errors Resolved  
**Ready**: Yes - Run tests with `python3 run_tests.py --config test_config.yaml`



