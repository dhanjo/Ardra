#!/bin/bash

# Function to install Go
install_go() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get install -y golang-go
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install go
    fi
}

# Function to install httprobe
install_httprobe() {
    go install github.com/tomnomnom/httprobe@latest
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    source ~/.bashrc
}

# Function to install findomain
install_findomain() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O findomain
        chmod +x findomain
        sudo mv findomain /usr/local/bin/
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-macos -O findomain
        chmod +x findomain
        sudo mv findomain /usr/local/bin/
    fi
}

# Function to install subfinder
install_subfinder() {
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    source ~/.bashrc
}

# Update package lists for Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew update
fi

# Install Go if not installed
if ! command -v go &> /dev/null; then
    echo "Go not found. Installing Go..."
    install_go
else
    echo "Go is already installed."
fi

# Install httprobe if not installed
if ! command -v httprobe &> /dev/null; then
    echo "Installing httprobe..."
    install_httprobe
else
    echo "httprobe is already installed."
fi

# Install findomain if not installed
if ! command -v findomain &> /dev/null; then
    echo "Installing findomain..."
    install_findomain
else
    echo "findomain is already installed."
fi

# Install subfinder if not installed
if ! command -v subfinder &> /dev/null; then
    echo "Installing subfinder..."
    install_subfinder
else
    echo "subfinder is already installed."
fi

echo "All required tools are installed and ready to use."
