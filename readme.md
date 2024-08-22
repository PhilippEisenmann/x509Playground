# mTLS test Client

Thsi respository contains a C# demo console application to connect to an TLS Web server using client certificates located in the local machine (Windows/Linux) certificate store

## Testing the Client using a http reflector

we can test the application unsing a https reflector with mTLS support.
we will use the docker image [mendhak/http-https-echo](https://github.com/mendhak/docker-http-https-echo/tree/master?tab=readme-ov-file#use-your-own-certificates)

### create a server certificate and trust it

    dotnet dev-certs https -np  --trust -ep ./testing/certificate.pem --format PEM

### change the app.config to use the docker endpoint

    <add key="url" value="https://localhost:8443" />
    <add key="SubjectDistinguishedName" value="CN=FirstNameLastName@fielmann.com" />

### launch the docker image and test the application

    cd testing
    docker compose up

    certificate_tool.exe > output.log
