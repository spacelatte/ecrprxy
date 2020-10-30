
# ecr-prxy: AWS ECR proxy with embedded authentication

Helper proxy to automatically authenticate to the AWS Eleastic Container Registry (ECR) using Go's native `net/http` module.

### Install

Execute `go get -u github.com/pvtmert/ecprxy`

### Usage

- If you have `awscli` installed: `ecrprxy -port=8000`
- For standalone config: `ecrprxy -port=8000 -region=eu-central-1 -accesskey=AKIAU... -secretkey=w0lPPA...`
- You can also use standard AWSCLI environment variables such as `AWS_PROFILE`, `AWS_ACCESS_KEY` and `AWS_SECRET_KEY`.

```
Usage of ecrprxy:
	-config string
		Configuration (YAML) file to read from
	-port int
		Listen Port
	-username string
		Username for frontend authentication
	-password string
		Password for frontend authentication
	-token string
		AWS session token
	-awsconfig string
		AWS CLI credentials file
	-region string
		AWS region
	-profile string
		AWS profile name
	-accesskey string
		AWS access key
	-secretkey string
		AWS secret key
	-endpoint string
		AWS ECR registry canonical URL
		Eg: https://account_id.dkr.ecr.eu-central-1.amazonaws.com
	-certfile string
		TLS certificate file
	-keyfile string
		TLS private key file
```

Example configuration file:
```yml
port: 8000
username: hello
password: world
AWSToken: ""
AWSConfig: ~/.aws/credentials
AWSRegion: eu-central-1
AWSProfile: myProfile
AWSAccessKey: AKIAU...
AWSSecretKey: w0lPPA...
AWSEndpoint: https://account_id.dkr.ecr.eu-central-1.amazonaws.com
TLSCertFile: /path/to/tls.crt
TLSKeyFile: /path/to/tls.pem
```
