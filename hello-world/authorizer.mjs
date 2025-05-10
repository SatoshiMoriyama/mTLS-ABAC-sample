export const authorizerHandler = async (event) => {
  console.log("> handler", JSON.stringify(event, null, 4));

  const clientCertSub = event.requestContext.identity.clientCert.subjectDN;

  const response = {
    principalId: clientCertSub,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: "allow",
          Resource: event.methodArn,
        },
      ],
    },
  };

  console.log("Authorizer Response", JSON.stringify(response, null, 4));
  return response;
};
