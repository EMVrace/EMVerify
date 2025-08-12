#!/usr/bin/env python3
"""
EMV Attack Vector Test Suite
Tests the three new attack vectors against the formal verification framework
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def check_tamarin_installation():
    """Check if Tamarin prover is available"""
    try:
        result = subprocess.run(['tamarin-prover', '--version'], 
                              capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def validate_spthy_syntax(file_path):
    """Validate Tamarin theory file syntax"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Basic syntax checks
        if not content.startswith('theory '):
            return False, "Theory file must start with 'theory'"
        
        if not content.strip().endswith('end'):
            return False, "Theory file must end with 'end'"
        
        # Check for balanced comments
        open_comments = content.count('/*')
        close_comments = content.count('*/')
        if open_comments != close_comments:
            return False, "Unbalanced comment blocks"
        
        return True, "Syntax validation passed"
    
    except Exception as e:
        return False, f"Error reading file: {e}"

def test_makefile_integration():
    """Test that our Makefile extensions work correctly"""
    
    makefile_path = Path(__file__).parent / "Makefile"
    
    try:
        with open(makefile_path, 'r') as f:
            makefile_content = f.read()
        
        # Check for our attack vector additions
        required_entries = [
            'attack = auth_downgrade',
            'generic=AttackVectors',
            'attacks:',
            'AttackVector_$(attack)',
            'AttackVectors.oracle'
        ]
        
        missing = []
        for entry in required_entries:
            if entry not in makefile_content:
                missing.append(entry)
        
        if missing:
            return False, f"Missing Makefile entries: {missing}"
        
        return True, "Makefile integration validated"
    
    except Exception as e:
        return False, f"Error validating Makefile: {e}"

def test_attack_implementations():
    """Test attack implementation documentation completeness"""
    
    attack_dir = Path(__file__).parent / "attack_implementations"
    
    required_files = [
        'vector1_auth_downgrade.md',
        'vector2_state_confusion.md', 
        'vector3_cross_kernel.md'
    ]
    
    missing_files = []
    for file_name in required_files:
        file_path = attack_dir / file_name
        if not file_path.exists():
            missing_files.append(file_name)
    
    if missing_files:
        return False, f"Missing implementation files: {missing_files}"
    
    # Check file content completeness
    import json
    
    config_path = Path(__file__).parent / "content_checks.json"
    try:
        with open(config_path, 'r') as config_file:
            content_checks = json.load(config_file)
    except Exception as e:
        return False, f"Error loading content checks configuration: {e}"
    
    for file_name, keywords in content_checks.items():
        file_path = attack_dir / file_name
        try:
            with open(file_path, 'r') as f:
                content = f.read().lower()
            
            missing_keywords = [kw for kw in keywords if kw.lower() not in content]
            if missing_keywords:
                return False, f"File {file_name} missing keywords: {missing_keywords}"
        
        except Exception as e:
            return False, f"Error reading {file_name}: {e}"
    
    return True, "Attack implementation documentation validated"

def run_formal_verification_test():
    """Test formal verification if Tamarin is available"""
    
    if not check_tamarin_installation():
        return True, "Tamarin not available - skipping formal verification"
    
    # Try to run a basic verification test
    try:
        result = subprocess.run([
            'make', 
            'generic=AttackVectors', 
            'attack=auth_downgrade',
            'lemma=downgrade_attack_feasible'
        ], capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            return True, "Formal verification test passed"
        else:
            return False, f"Verification failed: {result.stderr}"
    
    except subprocess.TimeoutExpired:
        return False, "Verification test timed out"
    except Exception as e:
        return False, f"Error running verification: {e}"

def generate_test_report():
    """Generate comprehensive test report"""
    
    print("="*60)
    print("EMV Attack Vector Implementation Test Report")
    print("="*60)
    print()
    
    tests = [
        ("Tamarin Installation", check_tamarin_installation),
        ("AttackVectors.spthy Syntax", lambda: validate_spthy_syntax("AttackVectors.spthy")),
        ("Makefile Integration", test_makefile_integration),
        ("Attack Documentation", test_attack_implementations),
        ("Formal Verification", run_formal_verification_test)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"Running test: {test_name}...")
        
        try:
            if test_name == "Tamarin Installation":
                # Special handling for boolean function
                success = test_func()
                message = "Available" if success else "Not available"
                results.append((test_name, success, message))
            else:
                success, message = test_func()
                results.append((test_name, success, message))
            
            status = "PASS" if success else "FAIL"
            print(f"  {status}: {message}")
        
        except Exception as e:
            results.append((test_name, False, f"Exception: {e}"))
            print(f"  FAIL: Exception: {e}")
        
        print()
    
    # Summary
    print("="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for test_name, success, message in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {test_name}")
        if not success:
            print(f"      {message}")
    
    print()
    print(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("All tests passed! Implementation is ready for deployment.")
        return True
    else:
        print("Some tests failed. Please review the implementation.")
        return False

if __name__ == "__main__":
    success = generate_test_report()
    sys.exit(0 if success else 1)