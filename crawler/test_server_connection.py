import requests

def test_server_connection(host, port):
    """
    Tries to connect to the cache server and prints the result.
    
    Args:
        host (str): The server host.
        port (int): The server port.
    """
    try:
        response = requests.get(f"http://{host}:{port}/")
        if response.ok:
            print("Server is up and running!")
        else:
            print(f"Server returned an error: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e}")

if __name__ == "__main__":
    # Using the host and port from your config.ini
    host, port = 'styx.ics.uci.edu', 9000
    test_server_connection(host, port)
