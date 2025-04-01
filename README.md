# Secure Password Manager

A secure, local password manager built with Flask that emphasizes security and ease of use. This application provides secure password storage with strong encryption, password generation, search functionality, and a mobile-friendly interface.

## Live Demo

Check out the live deployment of the application at: https://password-manager-c6vj.onrender.com/

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt && npm install && npm run sass
```

4. Initialize the database:
```bash
flask init-db
```

## Usage Examples

1. Start the development server:
```bash
python run.py
```

2. Access the application at `http://localhost:5000`

3. Create a new password entry:
   - Click "Add New Password"
   - Fill in the website/service name
   - Generate or enter a password
   - Save the entry

4. Search for passwords:
   - Use the search bar to filter entries
   - Click on any entry to view details

5. Generate secure passwords:
   - Click "Generate Password"
   - Customize length and character types
   - Copy the generated password

## License

This project is licensed under the MIT License - see the LICENSE file for details. 