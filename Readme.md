# Graphical MITM Proxy Tool

A graphical MITM (Man-In-The-Middle) proxy tool built in Rust with a user-friendly interface.

## Introduction

This project provides a graphical MITM proxy tool that allows users to intercept and inspect network traffic. It can automatically set up and restore system proxies, requiring administrator privileges only when a trusted CA is used.

## Features

 - Graphical user interface for managing MITM proxy settings.
 - Automatic system proxy setup and restoration.
 - Generates and trusts a CA certificate for intercepting SSL/TLS traffic.
 - No need to install various environments such as Python, a single executable file

## Usage

### Generating and Trusting CA

Click the "Generate CA" button to generate a CA certificate and private key. This step is only required for the first operation.

Click the "Trust CA" button to trust the generated CA certificate. This step is also required for the first operation.

### Starting the Proxy

After generating and trusting the CA, configure the proxy listening address in the UI.

Click the "Start Proxy" button to start the MITM proxy. The button will change to "Stop Proxy".

The query containing dispatchSeed or dispatch_seed in the request will be displayed in the log

To stop the proxy, click the "Stop Proxy" button.

## Contributing

Contributions are welcome! If you find any bugs or want to enhance the project, feel free to open issues or pull requests on the GitHub repository.

## License

This project is licensed under the MIT License.