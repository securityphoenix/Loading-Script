# Phoenix Loading Script V5 - Folder Structure Guide

## 📁 Complete Folder Organization

```
Utils/Loading_Script_V5/
│
├── 🎯 SYNTHETIC DATA GENERATOR SYSTEM
│   │
│   ├── synthetic-data-generator/                    ← Main Generator System
│   │   ├── generate_and_import_synthetic_data.py   ← Main script (1,200+ lines)
│   │   ├── synthetic_data_config.ini                ← Configuration file
│   │   ├── test_configs/                            ← Test configurations
│   │   │   ├── simple_test.ini                      ← Simple test (20 assets)
│   │   │   ├── per_class_test.ini                   ← Per-class test (240 assets)
│   │   │   └── README.md                            ← Test config guide
│   │   └── README.md                                ← Generator folder guide
│   │
│   ├── REFERENCE_DOCUMENTATION/
│   │   └── synthetic_data/                          ← All Synthetic Data Docs
│   │       ├── README.md                            ← Documentation folder guide
│   │       ├── SYNTHETIC_DATA_GETTING_STARTED.md    ← ⭐ START HERE
│   │       ├── SYNTHETIC_DATA_MASTER_INDEX.md       ← Complete doc index
│   │       │
│   │       ├── Core System (4 files)
│   │       │   ├── SYNTHETIC_DATA_SYSTEM_README.md
│   │       │   ├── SYNTHETIC_DATA_ARCHITECTURE.md
│   │       │   ├── SYNTHETIC_DATA_SYSTEM_SUMMARY.md
│   │       │   └── COMPLETE_SYSTEM_OVERVIEW.md
│   │       │
│   │       ├── Feature Guides (6 files)
│   │       │   ├── ASSET_DISTRIBUTION_GUIDE.md
│   │       │   ├── ASSET_DISTRIBUTION_ENHANCEMENT.md
│   │       │   ├── VULNERABILITY_COUNTS_CUSTOMIZATION.md
│   │       │   ├── VULNERABILITY_COUNTS_QUICK_REFERENCE.md
│   │       │   ├── VULNERABILITY_COUNT_ENHANCEMENT_SUMMARY.md
│   │       │   └── CONFIGURATION_EXAMPLES.md
│   │       │
│   │       └── Summaries (6 files)
│   │           ├── COMPLETE_CUSTOMIZATION_SUMMARY.md
│   │           ├── CUSTOMIZATION_VISUAL_GUIDE.md
│   │           ├── ENHANCEMENTS_COMPLETE_FINAL_SUMMARY.md
│   │           ├── SESSION_COMPLETE_SUMMARY.md
│   │           └── QUICK_START_SYNTHETIC_DATA.md
│   │
│   └── customization/                               ← Tag Configuration Files
│       ├── tags_config_infra_production.yaml       ← Infrastructure tags ✨ NEW
│       ├── tags_config_container_production.yaml   ← Container tags ✨ NEW
│       ├── tags_config_web_production.yaml         ← Web app tags ✨ NEW
│       ├── tags_config_cloud_production.yaml       ← Cloud tags ✨ NEW
│       ├── tags_config_code_production.yaml        ← Code/SAST tags ✨ NEW
│       ├── tags_config_dependency_production.yaml  ← Dependency tags ✨ NEW
│       ├── tags_config_PCI-NoSN.yaml               ← PCI compliance
│       ├── tags_config_PCI-NoSN_CIS.yaml           ← PCI + CIS
│       └── ... (other tag files)
│
├── 📚 GENERAL DOCUMENTATION
│   │
│   ├── REFERENCE_DOCUMENTATION/
│   │   ├── DOCUMENTATION_INDEX.md                   ← Main documentation index
│   │   ├── SYNTHETIC_DATA_GUIDE.md                  ← Data creation methods
│   │   ├── CUSTOMIZATION_GUIDE.md                   ← Complete customization
│   │   ├── TAG_CONFIGURATION_GUIDE.md               ← Tag system guide
│   │   ├── CONTAINER_METADATA_STANDARD.md           ← Container metadata
│   │   └── ... (other reference docs)
│   │
│   ├── SYNTHETIC_DATA_SYSTEM_INDEX.md               ← Quick navigation guide
│   ├── REORGANIZATION_COMPLETE.md                   ← This reorganization summary
│   └── FOLDER_STRUCTURE_GUIDE.md                    ← This file
│
└── 🔧 IMPORT SYSTEM (EXISTING)
    ├── phoenix_multi_scanner_enhanced.py            ← Main import script
    ├── phoenix_multi_scanner_import.py              ← Alternative import
    ├── phoenix_import_refactored.py                 ← Core import
    └── ... (other Loading Script V5 files)
```

---

## 🚀 Quick Navigation

### To Use the Generator

```bash
# 1. Navigate to generator folder
cd Utils/Loading_Script_V5/synthetic-data-generator

# 2. Read getting started
cat ../REFERENCE_DOCUMENTATION/synthetic_data/SYNTHETIC_DATA_GETTING_STARTED.md

# 3. Configure
nano synthetic_data_config.ini

# 4. Run
python generate_and_import_synthetic_data.py
```

### To Read Documentation

```bash
# Navigate to documentation folder
cd Utils/Loading_Script_V5/REFERENCE_DOCUMENTATION/synthetic_data

# View index
cat SYNTHETIC_DATA_MASTER_INDEX.md

# Read getting started
cat SYNTHETIC_DATA_GETTING_STARTED.md

# List all docs
ls -la
```

### To Modify Tags

```bash
# Navigate to customization folder
cd Utils/Loading_Script_V5/customization

# View existing tags
cat tags_config_infra_production.yaml

# Create custom tags
cp tags_config_infra_production.yaml my_custom_tags.yaml
nano my_custom_tags.yaml
```

---

## 📊 Directory Statistics

### Synthetic Data Generator System

| Component | Location | Files | Lines |
|-----------|----------|-------|-------|
| **Generator** | `synthetic-data-generator/` | 1 script + 1 config | 1,550+ |
| **Test Configs** | `synthetic-data-generator/test_configs/` | 2 configs + README | 150+ |
| **Documentation** | `REFERENCE_DOCUMENTATION/synthetic_data/` | 17 files | 9,000+ |
| **Tag Files** | `customization/` (6 new files) | 6 files | 600+ |
| **Total** | | **27 files** | **~11,300 lines** |

---

## 🎯 File Locations Reference

### Need to Generate Data?
→ `synthetic-data-generator/generate_and_import_synthetic_data.py`

### Need Configuration?
→ `synthetic-data-generator/synthetic_data_config.ini`

### Need Documentation?
→ `REFERENCE_DOCUMENTATION/synthetic_data/SYNTHETIC_DATA_GETTING_STARTED.md`

### Need Tag Files?
→ `customization/tags_config_*_production.yaml`

### Need Test Configs?
→ `synthetic-data-generator/test_configs/`

### Need Import Script?
→ `phoenix_multi_scanner_enhanced.py` (in root)

---

## 🔗 Path Relationships

### From Generator Folder

```bash
# Current: synthetic-data-generator/

# Import script
../phoenix_multi_scanner_enhanced.py

# Documentation
../REFERENCE_DOCUMENTATION/synthetic_data/

# Tag files
../customization/

# Test configs
./test_configs/
```

### From Root (Loading_Script_V5)

```bash
# Generator
./synthetic-data-generator/generate_and_import_synthetic_data.py

# Documentation
./REFERENCE_DOCUMENTATION/synthetic_data/

# Tag files
./customization/

# Quick index
./SYNTHETIC_DATA_SYSTEM_INDEX.md
```

---

## 📚 Documentation Organization

### By Purpose

**Getting Started**:
- `synthetic_data/SYNTHETIC_DATA_GETTING_STARTED.md` ⭐
- `synthetic_data/QUICK_START_SYNTHETIC_DATA.md`
- `synthetic_data/SYNTHETIC_DATA_MASTER_INDEX.md`

**Complete Reference**:
- `synthetic_data/SYNTHETIC_DATA_SYSTEM_README.md`
- `synthetic_data/SYNTHETIC_DATA_ARCHITECTURE.md`
- `SYNTHETIC_DATA_GUIDE.md` (in parent REFERENCE_DOCUMENTATION/)

**Feature Guides**:
- `synthetic_data/ASSET_DISTRIBUTION_GUIDE.md`
- `synthetic_data/VULNERABILITY_COUNTS_CUSTOMIZATION.md`
- `synthetic_data/CONFIGURATION_EXAMPLES.md`

**Quick References**:
- `synthetic_data/VULNERABILITY_COUNTS_QUICK_REFERENCE.md`
- `synthetic_data/COMPLETE_CUSTOMIZATION_SUMMARY.md`

---

## ✅ Organization Benefits

### Before Reorganization
```
❌ All files in root directory
❌ Documentation mixed with scripts
❌ Difficult to find specific guides
❌ No clear structure
```

### After Reorganization
```
✅ Generator system in dedicated folder
✅ Documentation centralized in synthetic_data/
✅ Easy to navigate
✅ Professional structure
✅ Clear separation of concerns
```

---

## 🎓 Navigation Cheat Sheet

### Want to Generate Data?
```bash
cd synthetic-data-generator
python generate_and_import_synthetic_data.py
```

### Want to Read Docs?
```bash
cd REFERENCE_DOCUMENTATION/synthetic_data
cat SYNTHETIC_DATA_GETTING_STARTED.md
```

### Want to Customize Tags?
```bash
cd customization
nano tags_config_infra_production.yaml
```

### Want Quick Reference?
```bash
cd Utils/Loading_Script_V5
cat SYNTHETIC_DATA_SYSTEM_INDEX.md
```

---

## 📊 Quick Stats

**Total System**:
- 1 main Python script (1,200+ lines)
- 1 main configuration (350+ lines)
- 6 production tag files (600+ lines)
- 17 documentation files (9,000+ lines)
- 2 test configurations
- 4 README/index files

**Organization**:
- 2 dedicated folders (generator + docs)
- Clear separation of concerns
- Professional structure
- Easy to navigate

---

## 🎉 System Status

**Reorganization**: ✅ Complete  
**Testing**: ✅ Passed (dry run successful)  
**Documentation**: ✅ Organized and accessible  
**Paths**: ✅ Verified and working  
**Production**: ✅ READY TO USE  

---

*Folder Structure Guide*
*Version: 1.2*
*Last Updated: February 2026*
*Status: Organized & Tested ✅*
