#!/usr/bin/env python3
import os
import secrets
import subprocess
import sys
from pathlib import Path

def generate_env_file():
    """Generate .env file with secure keys"""
    template = Path('.env.template').read_text()
    env_content = template.replace(
        'replace-with-a-real-secret-key', secrets.token_hex(32)
    ).replace(
        'replace-with-another-secret-key', secrets.token_hex(32)
    )
    Path('.env').write_text(env_content)
    print("✓ Generated .env file with secure keys")

def setup_directories():
    """Create necessary directories"""
    dirs = ['instance', 'logs', 'flask_session']
    for d in dirs:
        Path(d).mkdir(exist_ok=True)
        Path(f"{d}/.gitkeep").touch()
    print("✓ Created necessary directories")

def setup_python_env():
    """Set up Python virtual environment and install dependencies"""
    if not Path('venv').exists():
        subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
        print("✓ Created virtual environment")

    if os.name == 'nt':  # Windows
        pip = 'venv\\Scripts\\pip'
        activate = 'venv\\Scripts\\activate'
    else:  # Unix
        pip = 'venv/bin/pip'
        activate = 'source venv/bin/activate'

    subprocess.run([pip, 'install', '--upgrade', 'pip'], check=True)
    subprocess.run([pip, 'install', '-r', 'requirements.txt'], check=True)
    print("✓ Installed Python dependencies")
    print(f"\nActivate virtual environment with: {activate}")

def setup_frontend():
    """Set up frontend dependencies and build CSS"""
    if subprocess.run(['npm', '--version'], capture_output=True).returncode == 0:
        subprocess.run(['npm', 'install'], check=True)
        subprocess.run(['npm', 'run', 'sass'], check=True)
        print("✓ Built frontend assets")
    else:
        print("⚠ npm not found. Frontend assets not built.")

def main():
    print("Setting up Password Manager...")
    setup_directories()
    generate_env_file()
    setup_python_env()
    setup_frontend()
    
    print("\n✨ Setup complete! To start the application:")
    if os.name == 'nt':
        print("1. venv\\Scripts\\activate")
    else:
        print("1. source venv/bin/activate")
    print("2. python run.py")

if __name__ == '__main__':
    main()