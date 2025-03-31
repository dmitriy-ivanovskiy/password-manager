import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Get host and port from environment variables or use defaults
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5003))
    
    # Try to use the specified port, but increment if it's in use
    max_port_attempts = 10
    original_port = port
    
    for attempt in range(max_port_attempts):
        try:
            print(f"Starting server on {host}:{port}")
            app.run(host=host, port=port, debug=app.config.get('DEBUG', False))
            break  # If we get here, the server started successfully
        except OSError as e:
            if 'Address already in use' in str(e) and attempt < max_port_attempts - 1:
                port = original_port + attempt + 1
                print(f"Port {original_port + attempt} is in use, trying {port} instead...")
            else:
                print(f"Error starting server: {e}")
                raise 