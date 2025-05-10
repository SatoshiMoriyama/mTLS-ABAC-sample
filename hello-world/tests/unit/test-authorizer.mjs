'use strict';

import { expect } from 'chai';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const authorizer = require('../../authorizer.mjs');

// Mock the crypto module
const mockX509Certificate = {
    subject: 'CN=test-client,O=Test Organization,C=US'
};

const mockCrypto = {
    X509Certificate: function(cert) {
        if (cert === 'invalid-cert') {
            throw new Error('Invalid certificate');
        }
        return mockX509Certificate;
    }
};

// Replace the real crypto module with our mock
require.cache[require.resolve('crypto')] = {
    exports: mockCrypto
};

describe('Tests authorizer', function () {
    it('verifies successful mTLS authorization with client certificate', async () => {
        const event = {
            methodArn: 'arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/hello',
            requestContext: {
                identity: {
                    clientCert: {
                        clientCertPem: '-----BEGIN CERTIFICATE-----\nMIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\nADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\nb24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\nMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\nb3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\nca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\nIFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\nVOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\njgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\nA4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\nU5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\nN+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\no/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\nrqXRfboQnoZsG4q5WTP468SQvvG5\n-----END CERTIFICATE-----'
                    }
                }
            }
        };
        
        const result = await authorizer.handler(event);
        
        expect(result).to.be.an('object');
        expect(result.principalId).to.equal('CN=test-client,O=Test Organization,C=US');
        expect(result.context).to.be.an('object');
        expect(result.context.clientCertSub).to.equal('CN=test-client,O=Test Organization,C=US');
        expect(result.policyDocument).to.be.an('object');
        expect(result.policyDocument.Statement[0].Effect).to.equal('Allow');
        expect(result.policyDocument.Statement[0].Resource).to.equal(event.methodArn);
    });

    it('verifies denied authorization when client certificate is missing', async () => {
        const event = {
            methodArn: 'arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/hello',
            requestContext: {
                identity: {}
            }
        };
        
        const result = await authorizer.handler(event);
        
        expect(result).to.be.an('object');
        expect(result.principalId).to.equal('unauthorized');
        expect(result.context).to.be.an('object');
        expect(result.context.reason).to.equal('Client certificate required');
        expect(result.policyDocument).to.be.an('object');
        expect(result.policyDocument.Statement[0].Effect).to.equal('Deny');
        expect(result.policyDocument.Statement[0].Resource).to.equal(event.methodArn);
    });

    it('verifies denied authorization when client certificate is invalid', async () => {
        const event = {
            methodArn: 'arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/hello',
            requestContext: {
                identity: {
                    clientCert: {
                        clientCertPem: 'invalid-cert'
                    }
                }
            }
        };
        
        const result = await authorizer.handler(event);
        
        expect(result).to.be.an('object');
        expect(result.principalId).to.equal('unauthorized');
        expect(result.context).to.be.an('object');
        expect(result.context.reason).to.equal('Invalid client certificate');
        expect(result.policyDocument).to.be.an('object');
        expect(result.policyDocument.Statement[0].Effect).to.equal('Deny');
        expect(result.policyDocument.Statement[0].Resource).to.equal(event.methodArn);
    });
});