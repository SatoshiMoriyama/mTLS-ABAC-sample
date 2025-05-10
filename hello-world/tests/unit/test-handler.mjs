'use strict';

import { lambdaHandler } from '../../app.mjs';
import { expect } from 'chai';
var event, context;

describe('Tests index', function () {
    beforeEach(function() {
        // Default event object
        event = {
            headers: {}
        };
        context = {};
    });

    it('verifies successful response without issuer DN', async () => {
        const result = await lambdaHandler(event, context)

        expect(result).to.be.an('object');
        expect(result.statusCode).to.equal(200);
        expect(result.body).to.be.an('string');

        let response = JSON.parse(result.body);

        expect(response).to.be.an('object');
        expect(response.message).to.be.equal("hello world");
        expect(response.clientCertIssuerDN).to.be.equal("Not available");
    });

    it('verifies successful response with issuer DN', async () => {
        // Add the X-Certificate-IssuerDN header to the event
        event.headers = {
            "X-Certificate-IssuerDN": "CN=Amazon Root CA 1, O=Amazon, C=US"
        };
        
        const result = await lambdaHandler(event, context)

        expect(result).to.be.an('object');
        expect(result.statusCode).to.equal(200);
        expect(result.body).to.be.an('string');

        let response = JSON.parse(result.body);

        expect(response).to.be.an('object');
        expect(response.message).to.be.equal("hello world");
        expect(response.clientCertIssuerDN).to.be.equal("CN=Amazon Root CA 1, O=Amazon, C=US");
    });
});
