package it.arkhive.arkhive.Configuration;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;

import java.net.URI;

@Configuration
public class S3ClientConfiguration {

    @Value("${arkhive.s3.uri}")
    private String uri;
    @Value("${arkhive.s3.access-key}")
    private String accessKey;
    @Value("${arkhive.s3.secret-key}")
    private String secretKey;
    @Value("${arkhive.s3.bucket}")
    private String bucket;

    @Bean
    public S3Client s3client() {
        return S3Client.builder()
                .endpointOverride(URI.create(uri))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKey, secretKey)))
                .region(Region.EU_WEST_1)
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(true) // important for localstack
                        .build())
                .httpClientBuilder(ApacheHttpClient.builder())
                .build();
    }
}
