package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"gopkg.in/yaml.v2"
)

type proxyConfig struct {
	Port         *int     `yaml:"port"`
	AWSToken     *string  `yaml:"AWSToken"`
	AWSConfig    *string  `yaml:"AWSConfig"`
	AWSRegion    *string  `yaml:"AWSRegion"`
	AWSProfile   *string  `yaml:"AWSProfile"`
	AWSKeyAccess *string  `yaml:"AWSAccessKey"`
	AWSKeySecret *string  `yaml:"AWSSecretKey"`
	AWSEndpoint  *url.URL `yaml:"AWSEndpoint"`
	TLSCertFile  *string  `yaml:"TLSCertFile"`
	TLSKeyFile   *string  `yaml:"TLSKeyFile"`
	Username     *string  `yaml:"username"`
	Password     *string  `yaml:"password"`
}

type tokenDeadline struct {
	validUntil time.Time
	endpoint string
	repoURL url.URL
	token string
}

var localConfig proxyConfig
var urlTokenMap = make(map[url.URL]tokenDeadline)

func awsRepositoriesGet(connection *ecr.ECR) (*ecr.DescribeRepositoriesOutput, error) {
	input := new(ecr.DescribeRepositoriesInput)
	return connection.DescribeRepositories(input)
}

func awsAuthorizationGet(connection *ecr.ECR) (*ecr.GetAuthorizationTokenOutput, error) {
	input := new(ecr.GetAuthorizationTokenInput)
	return connection.GetAuthorizationToken(input)
}

func awsRepositoryToReverseProxy(repository *ecr.DescribeRepositoriesOutput) (*httputil.ReverseProxy, error) {
	if target, err := url.Parse(*repository.Repositories[0].RepositoryUri); err != nil {
		return nil, err
	} else {
		return httputil.NewSingleHostReverseProxy(target), nil
	}
}

func awsConfigGet(config proxyConfig) (*aws.Config) {
	awsConfig := aws.NewConfig()

	if config.AWSRegion != nil && *config.AWSRegion != "" {
		log.Println("Configuring AWS Region:", *config.AWSRegion)
		awsConfig.WithRegion(*config.AWSRegion)
	}
	//awsConfig.WithCredentials(credentials.NewEnvCredentials())
	awsConfig.WithCredentialsChainVerboseErrors(true)

	if (
		(config.AWSConfig  != nil && *config.AWSConfig  != "") ||
		(config.AWSProfile != nil && *config.AWSProfile != "") ||
	false) {
		log.Println("Configuring AWS Config and Profile:", *config.AWSConfig, *config.AWSProfile)
		awsConfig.WithCredentials(credentials.NewSharedCredentials(*config.AWSConfig, *config.AWSProfile))
	}

	if (
		(config.AWSKeyAccess != nil && config.AWSKeySecret != nil) &&
		(*config.AWSKeyAccess != "" && *config.AWSKeySecret != "") &&
	true) {
		log.Println("Configuring AWS Access Key, AWS Secret Key and AWS Session Token:", *config.AWSKeyAccess, *config.AWSToken)
		awsConfig.WithCredentials(credentials.NewStaticCredentials(*config.AWSKeyAccess, *config.AWSKeySecret, *config.AWSToken))
	}

	return awsConfig
}

func awsConnectionGet(config proxyConfig) (*session.Session, *ecr.ECR) {
		awsSession := session.Must(session.NewSession())
		connection := ecr.New(awsSession, awsConfigGet(localConfig))
		return awsSession, connection
}

func reqHandler(resp http.ResponseWriter, req *http.Request) {
	if (
		(localConfig.Username != nil && localConfig.Password != nil) &&
		(*localConfig.Username != "" && *localConfig.Password != "") &&
	true) {
		user, pass, state := req.BasicAuth()
		if !state || user != *localConfig.Username || pass != *localConfig.Password {
			log.Println("Rejecting invalid authentication from:", req.RemoteAddr, "state:", state, "user:", user)
			resp.WriteHeader(http.StatusForbidden)
			resp.Write([]byte(strconv.FormatBool(state)))
			return
		}
	}
	obj, exists := urlTokenMap[*req.URL]
	if !exists {
		log.Println("Auth Token for URL not found in cache (miss):", req.URL.String())
	} else if time.Now().After(obj.validUntil) {
		log.Println("Auth Token for URL is expired (expire):", req.URL.String(), obj.validUntil)
	}
	if !exists || time.Now().After(obj.validUntil) {
		_, connection := awsConnectionGet(localConfig)
		authorization, err := awsAuthorizationGet(connection)
		if err != nil {
			log.Println("Auth token retrieval is failed with:", err)
			resp.WriteHeader(http.StatusUnauthorized)
			resp.Write([]byte(err.Error()))
			return
		}
		index        := 0
		token        := *authorization.AuthorizationData[index].AuthorizationToken
		expires      := *authorization.AuthorizationData[index].ExpiresAt
		endpoint     := *authorization.AuthorizationData[index].ProxyEndpoint
		repoURL, _   := url.Parse(endpoint)
		obj = tokenDeadline {
			validUntil: expires,
			endpoint: endpoint,
			repoURL: *repoURL,
			token: token,
		}
		urlTokenMap[*req.URL] = obj
		log.Println("Caching token in memory for URL:", req.URL.String(), expires, endpoint, token[:16], "...")
	} else {
		log.Println("Auth token for URL is found in cache (hit):", req.URL.String())
	}
	req.Host     = obj.repoURL.Host
	req.URL.Host = obj.repoURL.Host
	req.Header.Set("Authorization", "Basic " + obj.token)
	httputil.NewSingleHostReverseProxy(&obj.repoURL).ServeHTTP(resp, req)
	decodedToken, _ := base64.StdEncoding.DecodeString(obj.token)
	log.Println(
		"Using:", obj.endpoint,
		"with:", string(decodedToken[:16]),
		"...", string(decodedToken[len(decodedToken)-16:]),
		"for:", req.URL.Path,
	)
	return
}

func setupListener(port *int) error {
	var result error
	var listen string
	log.Println("Testing AWS connection... (fail-fast)")
	_, connection := awsConnectionGet(localConfig)
	repositories, err := awsRepositoriesGet(connection)
	if err != nil {
		log.Println("AWS Connection failed! Error:", err.Error())
		return err
	}
	log.Println("AWS Connection successful.")
	for i, e := range repositories.Repositories {
		log.Println("Repository:", "(", i, ")", *e.RepositoryName)
	}
	http.HandleFunc("/", reqHandler)
	if (
		(localConfig.TLSCertFile != nil && localConfig.TLSKeyFile != nil) &&
		(*localConfig.TLSCertFile != "" && *localConfig.TLSKeyFile != "") &&
	true) {
		log.Println("TLS Configured:", *localConfig.TLSCertFile, *localConfig.TLSKeyFile)
		if *port == 0 {
			*port = 443
			log.Println("Port is not specified. Using default:", *port)
		}
		listen = fmt.Sprintf(":%d", *port)
		result = http.ListenAndServeTLS(listen,
			*localConfig.TLSCertFile,
			*localConfig.TLSKeyFile,
			nil)
	} else {
		if *port == 0 {
			*port = 80
			log.Println("Port is not specified. Using default:", *port)
		}
		listen = fmt.Sprintf(":%d", *port)
		result = http.ListenAndServe(listen, nil)
	}
	return result
}

func main() {
	localConfig.Port         = flag.Int("port",          0, "Listen Port")
	config                  := flag.String("config",    "", "Configuration (YAML) file to read from")
	endpoint                := flag.String("endpoint",  "", "AWS ECR registry canonical URL")
	localConfig.AWSToken     = flag.String("token",     "", "AWS session token")
	localConfig.AWSConfig    = flag.String("awsconfig", "", "AWS CLI credentials file")
	localConfig.AWSRegion    = flag.String("region",    "", "AWS region")
	localConfig.AWSProfile   = flag.String("profile",   "", "AWS profile name")
	localConfig.AWSKeyAccess = flag.String("accesskey", "", "AWS access key")
	localConfig.AWSKeySecret = flag.String("secretkey", "", "AWS secret key")
	localConfig.TLSCertFile  = flag.String("certfile",  "", "TLS certificate file")
	localConfig.TLSKeyFile   = flag.String("keyfile",   "", "TLS private key file")
	localConfig.Username     = flag.String("username",  "", "Basic Auth Username (frontend)")
	localConfig.Password     = flag.String("password",  "", "Basic Auth Password (frontend)")
	flag.Parse()
	if config != nil && *config != "" {
		data, err := ioutil.ReadFile(*config)
		if err != nil {
			panic(err)
		}
		yaml.Unmarshal(data, localConfig)
	}
	if endpoint != nil && *endpoint != "" {
		parsedURL, err := url.Parse(*endpoint)
		if err != nil {
			panic(err)
		}
		localConfig.AWSEndpoint = parsedURL
	}
	fmt.Println(setupListener(localConfig.Port))
	return
}
