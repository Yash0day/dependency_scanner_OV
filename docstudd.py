import argparse
import docker
import re
import requests
import json
import time

def run_docker_command(docker_image, output_file=None):  #Docker RUN
    start_time = time.time()  # Measure start time
    client = docker.from_env()
    volume_mapping = {"./": {"bind": "/home", "mode": "rw"}}   #Change the volumne mapping ./kraken/ to your own dir
    entrypoint = "bash"
    command = "/home/docan.sh"   #This file should be present in current dir.

    container = client.containers.run(
        docker_image,
        entrypoint=entrypoint,
        command=command,
        volumes=volume_mapping,
        remove=True,
        detach=True,
    )

    if output_file:
        with open(output_file, "w") as f:  #Stores all the packages list in the file installed_pakages
            for line in container.logs(stream=True):
                f.write(line.decode("utf-8").strip() + "\n")
    else:
        for line in container.logs(stream=True):
            print(line.decode("utf-8").strip())
    
    end_time = time.time()  # end time
    return end_time - start_time  # total time taken
            
def extract_packages(file_path):  #Extract/SImplify the Packages from the installed_pakages.txt
    packages = {}
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(r'(\S+)\s+(.+)', line)
            if match:
                package_name, version = match.groups()
                packages[package_name.lower()] = version.split('-')[0]
    return packages  #Returning a Dictionary of the form packageName:versionNumber

def fetch_vulnerabilities(package_name, version_number):
    start_time = time.time()  # start time
    url = 'https://api.osv.dev/v1/query'   #Link to the google osv API url
    payload = {  #OSV Post request
        "version": version_number,
        "package": {
            "name": package_name,
        }
    }

    response = requests.post(url, json=payload)
    elapsed_time = time.time() - start_time  # Measure elapsed time
    
    if response.content != b'{}':  #  Response is not empty
        response_json = response.json()  # Extract JSON content from the response
        return parse_json_response(response_json, package_name, elapsed_time)
            
    else:
        print(f"[-] No vulnerabilities found for package {package_name}.")
        return ""

def parse_json_response(response_json, package_name, elapsed_time):  # For report.html
    html_output = ""
    vulns = response_json.get('vulns', [])
    
    for vuln in vulns: 
        html_output += "<h3>[+] ID: " + vuln['id'] + "</h3>"
        html_output += "<p>[+] Description: " + vuln.get('details', vuln.get('summary', 'No description available')) + "</p>"
        html_output += "<p>[+] Affected Versions: " + str(vuln['affected']) + "</p>"
        html_output += "<p>[+] Alias: " + str(vuln.get('aliases', 'No aliases available')) + "</p>"
        html_output += "<p>[+] Time taken: " + str(round(elapsed_time / 60, 2)) + " minutes</p>"
        html_output += "<hr>"
    
    return html_output

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Docker command")
    parser.add_argument("-i", "--image", help="Name of the Docker image: `$docker images`", required=True)
    parser.add_argument("-o", "--output", help="Output file to write the Docker logs")
    args = parser.parse_args()

    total_time_start = time.time()  # start time

    run_docker_command(args.image, args.output)  #Docker RUN

    file_path = "installed_packages.txt"  #File where the package list is stored
    packages = extract_packages(file_path)

    html_report = "<html><head><title>Vulnerability Report - OSV DB</title></head><body>"

    for package, version in packages.items():
        print("\t [*] Scanning ^ - ^ ", package , ":", version)
        html_report += fetch_vulnerabilities(package, version)  #Adding ot the html file

    html_report += "</body></html>"

    with open("report.html", "w") as f:
        f.write(html_report)
    
    total_time_end = time.time()  
    total_time_taken = total_time_end - total_time_start  #Time for report formation
    
    print(f"[ = ] Total time taken: {round(total_time_taken / 60, 2)} minutes") #-> Put htis in the html file


