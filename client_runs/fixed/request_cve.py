import json
import requests
import os

# File patterns for includes and excludes
INCLUDES = {
    "go": ["**/*.go"],
    "python": ["**/*.py", "pyproject.toml", "setup.py", "setup.cfg"],
    "java": ["**/*.java", "settings.gradle", "src/main/**/*"],
    "javascript": ["**/*.js", "**/*.jsx", "webpack.config.js", "rollup.config.js", "babel.config.js", ".babelrc", ".eslintrc.js", ".eslintrc.json", "tsconfig.json", "*.config.js", "*.config.json", "public/**/*", "src/**/*"],
    "typescript": ["**/*.ts", "**/*.tsx", "tsconfig.json", "tsconfig.*.json", "webpack.config.js", "webpack.config.ts", "rollup.config.js", "rollup.config.ts", "babel.config.js", ".babelrc", ".eslintrc.js", ".eslintrc.json", "*.config.js", "*.config.ts", "*.json", "src/**/*", "public/**/*", "assets/**/*"],
    "dockerfile": ["Dockerfile*", "docker-compose.yml", "*.dockerfile", "*.dockerignore", "docker-compose.*.yml", "*.sh", "scripts/**/*", "*.env", "*.yaml", "*.yml", "*.json", "config/**/*", "conf.d/**/*"],
    "docs": ["**/*.md", "docs/**/*.rst"]
}

EXCLUDES = {
    "go": ["test/**/*", "**/vendor/**/*", "go.mod", "go.sum"],
    "java": ["target/**/*", "build/**/*", "*.class", ".gradle/**/*", ".mvn/**/*", ".gitignore", "test/**/*", "tests/**/*", "src/test/**/*", "pom.xml", "build.gradle"],
    "javascript": ["node_modules/**/*", "dist/**/*", "build/**/*", "test/**/*", "tests/**/*", "example/**/*", "examples/**/*", "package.json", "package-lock.json", "yarn.lock"],
    "typescript": ["node_modules/**/*", "dist/**/*", "build/**/*", "test/**/*", "tests/**/*", "example/**/*", "examples/**/*", "package.json", "package-lock.json", "yarn.lock"],
    "python": ["tests/**/*", "test/**/*", "venv/**/*", ".venv/**/*", "env/**/*", "build/**/*", "dist/**/*", ".mypy_cache/**/*", ".pytest_cache/**/*", "__pycache__/**/*", "*.pyc", "*.pyo", "*.pyd", "requirements.txt", "Pipfile", "Pipfile.lock"]
}

SUPPORTED_LANGUAGES = ["Go", "Python", "Dockerfile", "Java", "TypeScript", "JavaScript"]

# Load JSON data from file
def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Get repository information from SBOM data
def get_repo_info(data):
    source_code_repo = doc_repo = ""
    source_code_tag = doc_tag = ""
    
    for prop in data['metadata']['properties']:
        if "source-location" in prop['name']:
            source_code_repo = doc_repo = prop["value"]
        if "commit.id" in prop['name']:
            source_code_tag = doc_tag = prop["value"]
    
    return source_code_repo, source_code_tag, doc_repo, doc_tag

# Get languages from GitHub repository
def get_repo_languages(repo_url):
    repo = repo_url.replace('https://github.com', '')
    url = f"https://api.github.com/repos{repo}/languages"
    response = requests.get(url)
    if response.status_code == 200:
        return list(response.json().keys())
    return []

# Create includes and excludes lists based on languages
def create_includes_excludes(languages):
    includes = []
    excludes = []
    
    for lang in languages:
        if lang.lower() in INCLUDES:
            includes.extend(INCLUDES[lang.lower()])
        if lang.lower() in EXCLUDES:
            excludes.extend(EXCLUDES[lang.lower()])
    
    return includes, excludes

# Extract package information from SBOM data
def extract_packages(data):
    packages = []
    for component in data["components"]:
        package = {
            "name": component["name"],
            "version": component["version"],
            "purl": component.get("purl", " "),
            "system": next((prop["value"] for prop in component["properties"] if prop["name"] == "syft:package:type"), "")
        }
        packages.append(package)
    return packages

# Build the request payload
def build_request(request_id, cve, image_name, image_version, source_code_repo, source_code_tag, doc_repo, doc_tag, includes, excludes, packages):
    input_message = load_json('./sampleruntime.json')
    input_message["scan"]["id"] = request_id
    input_message["scan"]["vulns"] = [{"vuln_id": cve}]
    input_message["image"]["source_info"] = [
        {
            "type": "git",
            "source_type": "code",
            "git_repo": source_code_repo,
            "ref": source_code_tag,
            "include": includes,
            "exclude": excludes
        },
        {
            "type": "git",
            "source_type": "doc",
            "git_repo": doc_repo,
            "ref": doc_tag,
            "include": ["**/*.md", "docs/**/*.rst"],
            "exclude": []
        }
    ]
    input_message["image"]["name"] = image_name
    input_message["image"]["tag"] = image_version
    input_message["image"]["sbom_info"]["_type"] = "manual"
    input_message["image"]["sbom_info"]["packages"] = packages
    return input_message

def process_scan(request_id, runs, image, cve):
    # Pull Docker image and generate SBOM
    if not os.path.exists(f'{request_id}_cyclone.json'):
        os.system(f'docker pull {image}; syft {image} --scope all-layers -o cyclonedx-json -q | jq . > {request_id}_cyclone.json')
    
    # Load SBOM data
    sbom_data = load_json(f'{request_id}_cyclone.json')
    
    # Get repository information
    source_code_repo, source_code_tag, doc_repo, doc_tag = get_repo_info(sbom_data)
    
    # Get repository languages
    languages = get_repo_languages(source_code_repo)
    cve_languages = list(set(languages) & set(SUPPORTED_LANGUAGES))
    
    # Create includes and excludes
    includes, excludes = create_includes_excludes(cve_languages)
    
    # Extract packages
    packages = extract_packages(sbom_data)
    
    # Get image name and version
    image_name = sbom_data["metadata"]["component"]["name"]
    image_version = sbom_data["metadata"]["component"]["version"]

    cve_request = request_id + str(runs)
    # Build the request
    request_payload = build_request(cve_request, cve, image_name, image_version, source_code_repo, source_code_tag, doc_repo, doc_tag, includes, excludes, packages)
    # Send the request
    response = requests.post("http://localhost:8080/scan",json=request_payload)
    print(response.status_code)
    return response.status_code