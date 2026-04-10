import sys
import os
import subprocess

def run_container(url):
    # 1. Get absolute paths for volume mapping
    # We need to map the Windows folder "sandbox/output" to the Docker folder "/app/output"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(current_dir, 'output')
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    print(f"--- Host: Starting Docker Scan for {url} ---")
    print(f"--- Host: Mapping {output_dir} <--> /app/output ---")

    # 2. Construct the Docker Command
    # --rm: Delete container after it finishes (saves space)
    # -v: Volume map (So Windows can see the results)
    # Note: We do NOT use '-it' here because it runs in the background
    command = [
        "docker", "run", "--rm",
        "-v", f"{output_dir}:/app/output",
        "phishing-scanner-sandbox",  # The image name we built
        "python", "guest_scanner.py", url
    ]

    try:
        # 3. Run the command and wait for it to finish
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True
        )
        print("--- Host: Docker finished successfully ---")
        print(result.stdout)
        return True

    except subprocess.CalledProcessError as e:
        print(f"--- Host: Docker Failed (Exit Code {e.returncode}) ---")
        print(f"Error Output: {e.stderr}")
        return False
    except Exception as e:
        print(f"--- Host: Critical Error: {e} ---")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
        run_container(target_url)
    else:
        print("Usage: python host_orchestrator.py <URL>")